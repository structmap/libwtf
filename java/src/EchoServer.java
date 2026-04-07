import com.structmap.webtransportfast.*;

import java.io.IOException;
import java.lang.foreign.*;

class EchoServer {
    static {
        // this needs VM option -Djava.library.path to directory
        System.loadLibrary("msquic");
        System.loadLibrary("wtf");
    }
    static void log_callback(int level, MemorySegment component, MemorySegment file, int line,
                             MemorySegment message, MemorySegment user_context) {
        String[] logLevels = {
          "WTF_LOG_LEVEL_TRACE", // 0
          "WTF_LOG_LEVEL_DEBUG", // 1
          "WTF_LOG_LEVEL_INFO", // 2
          "WTF_LOG_LEVEL_WARN", // 3
          "WTF_LOG_LEVEL_ERROR", // 4
          "WTF_LOG_LEVEL_CRITICAL", // 5
          "WTF_LOG_LEVEL_NONE" // 6
        };
        System.out.println(logLevels[level] + "\t" + message.getString(0));
    }
    static void main() {

        System.out.println("Starting echo server...");
        var server = new WebTransportServer(8443, "cert.pem", "key.pem");
        if (!server.Start()) {
            return;
        }
        try {
            System.in.read();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        server.Stop();
    }
}