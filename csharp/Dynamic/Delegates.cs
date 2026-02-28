using System.Runtime.InteropServices;

namespace Structmap.WebTransportFast.Dynamic;

//typedef wtf_connection_decision_t (*wtf_connection_validator_t)(const wtf_connection_request_t* request, void* user_context);
//delegate* unmanaged[Cdecl]<wtf_connection_request_t*, IntPtr, wtf_connection_decision_t>=IntPtr
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate wtf_connection_decision_t ConnectionValidator(IntPtr request, IntPtr user_context);

//typedef void (*wtf_log_callback_t)(wtf_log_level_t level, const char* component, const char* file, int line, const char* message, void* user_context);
//delegate* unmanaged[Cdecl]<wtf_log_level_t, IntPtr, IntPtr, int, IntPtr, IntPtr, void>=IntPtr
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void LogCallback(wtf_log_level_t level, IntPtr component, IntPtr file, Int32 line, IntPtr message, IntPtr user_context);

//typedef void (*wtf_session_callback_t)(const wtf_session_event_t* event);
//delegate* unmanaged[Cdecl]<wtf_session_event_t*, void>=IntPtr
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void SessionCallback(IntPtr evt);
