// Expose malloc and free to simplify buffer management when calling the
// wtf_stream_send method (see wtf_stream_cleanup_send_context).

using System.Runtime.InteropServices;

namespace Structmap.WebTransportFast;

public static unsafe partial class MemoryAllocator
{

#if WINDOWS
    public const string DllName = "ucrtbase";
#else
    public const string DllName = "wtf";
#endif

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern IntPtr malloc([NativeTypeName("size_t")] UIntPtr n);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void free([NativeTypeName("void *")] IntPtr p);
}
