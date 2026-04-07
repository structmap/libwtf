import com.structmap.webtransportfast.*;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;
import java.util.function.Supplier;

class WebTransportServer {
    static {
        // this needs VM option -Djava.library.path to directory
        System.loadLibrary("msquic");
        System.loadLibrary("wtf");
    }

    public MemorySegment g_context;
    public MemorySegment g_server;
    public int port;
    public String cert;
    public String key;
    public Arena arena;

    public WebTransportServer(int port, String cert, String key) {
        this.port = port;
        this.cert = cert;
        this.key = key;
        this.sessions = new ConcurrentHashMap<>();
        this.sessionCallback = this::session_callback;
        this.channelFactory = () -> new LinkedBlockingQueue<>(10);
        this.handler = (ch) -> {
            // TODO handle channel closure
            while (true) {
                try {
                    var msg = ch.take();
                    if (msg instanceof Datagram dg) {
                        System.out.printf("[SERVER] Received message: %s\n", msg);
                        this.Send(dg.Context.Identifier, dg.Payload);
                    }
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        };
        this.arena = new MemoryAllocator();
    }

    public ConcurrentHashMap<Object, BlockingQueue<Object>> sessions;

    public Supplier<BlockingQueue<Object>> channelFactory;
    public Consumer<BlockingQueue<Object>> handler;

    public wtf_log_callback_t.Function logCallback;
    public wtf_connection_validator_t.Function connectionValidator;
    public wtf_session_callback_t.Function sessionCallback;
    public wtf_stream_callback_t.Function streamCallback;

    public record Session(WebTransportServer Server, Object Identifier) {
    }

    public record Datagram(Session Context, byte[] Payload) {
    }

    void session_callback(MemorySegment evt) {
        if (wtf_session_event_t.type(evt) == wtf_h.WTF_SESSION_EVENT_CONNECTED()) {
            var sessionPointer = wtf_session_event_t.session(evt);
            System.out.printf("[SESSION] New session connected 0x%x\n", sessionPointer.address());
            var ch = this.channelFactory.get();
            this.sessions.put(sessionPointer, ch);
            Thread.startVirtualThread(() -> this.handler.accept(ch));
            return;
        }
        if (wtf_session_event_t.type(evt) == wtf_h.WTF_SESSION_EVENT_DATAGRAM_RECEIVED()) {
            var sessionPointer = wtf_session_event_t.session(evt);
            var dr = wtf_session_event_t.datagram_received(evt);
            var n = wtf_session_event_t.datagram_received.length(dr);
            System.out.printf("[DATAGRAM] Received on session 0x%x (%d bytes)\n", sessionPointer.address(), n);
            var d = new Datagram(new Session(this, sessionPointer), new byte[(int) n]);
            var dataPtr = wtf_session_event_t.datagram_received.data(dr);
            MemorySegment.copy(dataPtr, ValueLayout.JAVA_BYTE, 0, d.Payload, 0, (int) n);
            var ch = this.sessions.get(sessionPointer);
            if (ch != null) {
                ch.offer(d); // TODO: warn on dropped datagram (even better would be to nack at protocol level)
            } else {
                System.err.printf("No channel for session 0x%x\n", sessionPointer.address());
            }
            return;
        }
        if (wtf_session_event_t.type(evt) == wtf_h.WTF_SESSION_EVENT_DATAGRAM_SEND_STATE_CHANGE()) {
            var dsc = wtf_session_event_t.datagram_send_state_changed(evt);
            var sendState = wtf_session_event_t.datagram_send_state_changed.state(dsc);
            var mightResend = sendState < wtf_h.WTF_DATAGRAM_SEND_LOST_DISCARDED();

            if (!mightResend) {
                var bufferCount = wtf_session_event_t.datagram_send_state_changed.buffer_count(dsc);
                var buffers = wtf_session_event_t.datagram_send_state_changed.buffers(dsc);

                for (int i = 0; i < bufferCount; i++) {
                    var buffer = wtf_buffer_t.asSlice(buffers, i);
                    var data = wtf_buffer_t.data(buffer);

                    if (data != null && data.address() != 0) {
                        ((MemoryAllocator) arena).free(data);
                    }
                }
            }
            return;
        }
    }

    public boolean Send(Object session, byte[] data) {
        var n = data.length;
        var dst = arena.allocate(n);
        MemorySegment.copy(data, 0, dst, ValueLayout.JAVA_BYTE, 0, n);

        var buffer = wtf_buffer_t.allocate(arena);
        wtf_buffer_t.data(buffer, dst);
        wtf_buffer_t.length(buffer, n);

        if (session instanceof MemorySegment sessionPtr) {
            int result = wtf_h.wtf_session_send_datagram(sessionPtr, buffer, 1);
            if (result != wtf_h.WTF_SUCCESS()) {
                var msg = wtf_h.wtf_result_to_string(result);
                System.out.printf("[DATAGRAM] Failed to echo: %s\n", msg.getString(0));
                return false;
            }
            System.out.printf("[DATAGRAM] Echoed %d bytes\n", n);
            return true;
        }

        return false;
    }

    boolean Start() {
        var logCallback = wtf_log_callback_t.allocate(
                this.logCallback,
                arena
        );
        var context_config = wtf_context_config_t.allocate(arena);
        wtf_context_config_t.log_level(context_config, wtf_h.WTF_LOG_LEVEL_TRACE());
        wtf_context_config_t.log_callback(context_config, logCallback);
        wtf_context_config_t.worker_thread_count(context_config, 4);
        wtf_context_config_t.enable_load_balancing(context_config, true);
        g_context = arena.allocate(ValueLayout.ADDRESS);
        var status = wtf_h.wtf_context_create(context_config, g_context);
        if (status != wtf_h.WTF_SUCCESS()) {
            var msg = wtf_h.wtf_result_to_string(status);
            System.out.printf("[ERROR] Failed to create context: %s\n", msg.getString(0));
        }

        var cert_data = wtf_certificate_config_t.cert_data.file.allocate(arena);
        wtf_certificate_config_t.cert_data.file.cert_path(cert_data, arena.allocateFrom(this.cert));
        wtf_certificate_config_t.cert_data.file.key_path(cert_data, arena.allocateFrom(this.key));

        var cert_config = wtf_certificate_config_t.allocate(arena);
        wtf_certificate_config_t.cert_type(cert_config, wtf_h.WTF_CERT_TYPE_FILE());
        wtf_certificate_config_t.cert_data.file(
                wtf_certificate_config_t.cert_data(cert_config),
                cert_data
        );

        var sessionCallback = wtf_session_callback_t.allocate(
                this.sessionCallback,
                arena
        );
        var connectionValidator = wtf_connection_validator_t.allocate(
                this.connectionValidator,
                arena
        );

        var server_config = wtf_server_config_t.allocate(arena);
        wtf_server_config_t.port(server_config, (short)this.port);
        wtf_server_config_t.cert_config(server_config, cert_config);
        wtf_server_config_t.session_callback(server_config, sessionCallback);
        wtf_server_config_t.connection_validator(server_config, connectionValidator);
        wtf_server_config_t.max_sessions_per_connection(server_config, 32);
        wtf_server_config_t.max_streams_per_session(server_config, 256);
        wtf_server_config_t.idle_timeout_ms(server_config, 60000);
        wtf_server_config_t.handshake_timeout_ms(server_config, 10000);
        wtf_server_config_t.enable_0rtt(server_config, true);
        wtf_server_config_t.enable_migration(server_config, true);

        g_server = arena.allocate(ValueLayout.ADDRESS);
        status = wtf_h.wtf_server_create(g_context.get(ValueLayout.ADDRESS, 0), server_config, g_server);
        if (status != wtf_h.WTF_SUCCESS()) {
            var msg = wtf_h.wtf_result_to_string(status);
            System.out.printf("[ERROR] Failed to create server: %s\n", msg.getString(0));
        }

        status = wtf_h.wtf_server_start(g_server.get(ValueLayout.ADDRESS, 0));
        if (status != wtf_h.WTF_SUCCESS()) {
            var msg = wtf_h.wtf_result_to_string(status);
            System.out.printf("[ERROR] Failed to start server: %s\n", msg.getString(0));
            return false;
        }
        return true;
    }

    void Stop() {
        wtf_h.wtf_server_stop(g_server.get(ValueLayout.ADDRESS, 0));
        wtf_h.wtf_server_destroy(g_server.get(ValueLayout.ADDRESS, 0));
        wtf_h.wtf_context_destroy(g_context.get(ValueLayout.ADDRESS, 0));
    }
}