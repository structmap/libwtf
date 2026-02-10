// Expose malloc and free to simplify buffer management when calling the
// wtf_stream_send method (see wtf_stream_cleanup_send_context).

using System.Runtime.InteropServices;

namespace Structmap.WebTransportFast;

public static unsafe partial class MemoryAllocator
{
    [DllImport("wtf", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern IntPtr malloc([NativeTypeName("size_t")] UIntPtr n);

    [DllImport("wtf", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    public static extern void free([NativeTypeName("void *")] IntPtr p);
}
