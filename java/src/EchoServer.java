import com.structmap.webtransportfast.*;

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

        wtf_h.wtf_context_destroy(g_context.get(ValueLayout.ADDRESS, 0));

//        Linker nativeLinker = Linker.nativeLinker();
//        SymbolLookup stdlib = nativeLinker.defaultLookup();
//        MemorySegment malloc = stdlib.find("malloc").orElseThrow();
//        System.out.printf("%x\n", malloc.address());

    }
}