package com.structmap.webtransportfast;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.ArrayList;
import java.util.List;

public class MemoryAllocator implements Arena {

    private static final Linker LINKER = Linker.nativeLinker();

    private static final MethodHandle MALLOC;
    private static final MethodHandle FREE;

    static {
        SymbolLookup stdlib = LINKER.defaultLookup();

        MALLOC = LINKER.downcallHandle(
                stdlib.find("malloc").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
        );

        FREE = LINKER.downcallHandle(
                stdlib.find("free").orElseThrow(),
                FunctionDescriptor.ofVoid(ValueLayout.ADDRESS)
        );
    }

    private final List<MemorySegment> allocatedSegments = new ArrayList<>();
    private boolean closed = false;

    @Override
    public MemorySegment allocate(long byteSize, long byteAlignment) {
        if (closed) {
            throw new IllegalStateException("Arena is closed");
        }

        try {
            MemorySegment address = (MemorySegment) MALLOC.invoke(byteSize);
            if (address.address() == 0) {
                throw new OutOfMemoryError("malloc failed");
            }

            MemorySegment segment = address.reinterpret(byteSize, this, null);
            allocatedSegments.add(segment);
            return segment;
        } catch (Throwable e) {
            throw new RuntimeException("Failed to allocate memory", e);
        }
    }

    public void free(MemorySegment segment) {
        if (closed) {
            throw new IllegalStateException("Arena is closed");
        }

        if (segment == null) {
            return;
        }

        try {
            FREE.invoke(segment);
            allocatedSegments.remove(segment);
        } catch (Throwable e) {
            throw new RuntimeException("Failed to free memory", e);
        }
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }

        closed = true;
        for (MemorySegment segment : allocatedSegments) {
            try {
                FREE.invoke(segment);
            } catch (Throwable e) {
                // Log or handle error, but continue freeing other segments
            }
        }
        allocatedSegments.clear();
    }

    @Override
    public MemorySegment.Scope scope() {
        return Arena.ofAuto().scope();
    }
}
