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
                var jarFolder = String.format("/native/%s-%s/", plat, arch);
                var tempDir = Files.createTempDirectory("native");
                System.out.println(tempDir.toAbsolutePath());
                String[] libraryNames = {"msquic", "wtf"};
                for (String libName : libraryNames) {
                    var mappedLibName = System.mapLibraryName(libName);
                    var in = WebTransportFast.class.getResourceAsStream(jarFolder + mappedLibName);
                    System.out.println(jarFolder + mappedLibName);
                    if (in == null) {
                        return false;
                    }
                    var tempPath = tempDir.resolve(mappedLibName).toAbsolutePath();
                    Files.copy(in, tempPath);
                    System.load(tempPath.toString());
                }
            } catch (IOException | UnsatisfiedLinkError | NullPointerException e) {
                System.err.println("Failed to load library: " + e.getMessage());
                return false;
            }
        }
        return (loaded = true);
    }
}
