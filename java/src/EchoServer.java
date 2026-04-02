import com.structmap.webtransportfast.*;

import java.io.IOException;
import java.lang.foreign.*;

class EchoServer {
    static {
        // this needs VM option -Djava.library.path to directory
        System.loadLibrary("msquic");
        System.loadLibrary("wtf");
    }
    public static void main() {
        System.out.println("Starting echo server...");

        var arena = Arena.global();
        var context_config = wtf_context_config_t.allocate(arena);
        wtf_context_config_t.log_level(context_config, wtf_h.WTF_LOG_LEVEL_TRACE());
        wtf_context_config_t.log_callback(context_config, MemorySegment.NULL);
        wtf_context_config_t.worker_thread_count(context_config, 4);
        wtf_context_config_t.enable_load_balancing(context_config, true);

        var g_context = arena.allocate(ValueLayout.ADDRESS);
        var status = wtf_h.wtf_context_create(context_config, g_context);
        if (status != wtf_h.WTF_SUCCESS()) {
            var msg = wtf_h.wtf_result_to_string(status);
            System.out.printf("[ERROR] Failed to create context: %s\n", msg.getString(0));
        }

        var cert_data = wtf_certificate_config_t.cert_data.file.allocate(arena);
        wtf_certificate_config_t.cert_data.file.cert_path(cert_data, arena.allocateFrom("cert.pem"));
        wtf_certificate_config_t.cert_data.file.key_path(cert_data, arena.allocateFrom("key.pem"));

        var cert_config = wtf_certificate_config_t.allocate(arena);
        wtf_certificate_config_t.cert_type(cert_config, wtf_h.WTF_CERT_TYPE_FILE());
        wtf_certificate_config_t.cert_data.file(
                wtf_certificate_config_t.cert_data(cert_config),
                cert_data
        );

        var server_config = wtf_server_config_t.allocate(arena);
        wtf_server_config_t.port(server_config, (short)8443);
        wtf_server_config_t.cert_config(server_config, cert_config);
        wtf_server_config_t.session_callback(server_config, MemorySegment.NULL);
        wtf_server_config_t.connection_validator(server_config, MemorySegment.NULL);
        wtf_server_config_t.max_sessions_per_connection(server_config, 32);
        wtf_server_config_t.max_streams_per_session(server_config, 256);
        wtf_server_config_t.idle_timeout_ms(server_config, 60000);
        wtf_server_config_t.handshake_timeout_ms(server_config, 10000);
        wtf_server_config_t.enable_0rtt(server_config, true);
        wtf_server_config_t.enable_migration(server_config, true);

        var g_server = arena.allocate(ValueLayout.ADDRESS);
        status = wtf_h.wtf_server_create(g_context.get(ValueLayout.ADDRESS, 0), server_config, g_server);
        if (status != wtf_h.WTF_SUCCESS()) {
            var msg = wtf_h.wtf_result_to_string(status);
            System.out.printf("[ERROR] Failed to create server: %s\n", msg.getString(0));
        }

        status = wtf_h.wtf_server_start(g_server.get(ValueLayout.ADDRESS, 0));
        if (status != wtf_h.WTF_SUCCESS()) {
            var msg = wtf_h.wtf_result_to_string(status);
            System.out.printf("[ERROR] Failed to start server: %s\n", msg.getString(0));
        }

        try {
            System.in.read();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        wtf_h.wtf_server_stop(g_server.get(ValueLayout.ADDRESS, 0));
        wtf_h.wtf_server_destroy(g_server.get(ValueLayout.ADDRESS, 0));
        wtf_h.wtf_context_destroy(g_context.get(ValueLayout.ADDRESS, 0));

//        Linker nativeLinker = Linker.nativeLinker();
//        SymbolLookup stdlib = nativeLinker.defaultLookup();
//        MemorySegment malloc = stdlib.find("malloc").orElseThrow();
//        System.out.printf("%x\n", malloc.address());

    }
}