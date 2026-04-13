package com.structmap.webtransportfast;

import java.io.IOException;
import java.nio.file.Files;

public class WebTransportFast {

    private static final Object loading = new Object();
    private static boolean loaded = false;

    public static boolean load() {
        synchronized (loading) {
            if (loaded) return true;
            try {
                var plat = System.getProperty("os.name").toLowerCase();
                var arch = System.getProperty("os.arch").toLowerCase();
                if (plat.equals("windows 11")) {
                    plat = "windows";
                }
                if (plat.equals("mac os x")) {
                    plat = "macosx";
                }
                if (arch.equals("amd64")) {
                    arch = "x86_64";
                }
                if (arch.equals("aarch64")) {
                    arch = "arm64";
                }
                var jarFolder = String.format("/native/%s-%s/", plat, arch);
                var tempDir = Files.createTempDirectory("native");
                var libmsquic = System.mapLibraryName("msquic");
                var libwtf = System.mapLibraryName("wtf");
                for (String lib : new String[] { libmsquic, libwtf }) {
                    var in = WebTransportFast.class.getResourceAsStream(jarFolder + lib);
                    if (in != null) {
                        var tempPath = tempDir.resolve(lib);
                        Files.copy(in, tempPath);
                    }
                }
                System.load(tempDir.resolve(libwtf).toAbsolutePath().toString());
            } catch (IOException | UnsatisfiedLinkError | NullPointerException e) {
                System.err.println("Failed to load library: " + e.getMessage());
                return false;
            }
        }
        return (loaded = true);
    }
}
