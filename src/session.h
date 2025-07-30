#ifndef WTF_SESSION_H
#define WTF_SESSION_H
#include "types.h"
#ifdef __cplusplus
extern "C" {
#endif

wtf_session* wtf_session_create(wtf_connection* conn, wtf_http3_stream* connect_stream);
void wtf_session_destroy(wtf_session* session);
wtf_result_t wtf_session_send_capsule(wtf_session* session, uint64_t type, const uint8_t* data,
                                      size_t length);
void wtf_session_destroy(wtf_session* session);


bool wtf_session_process_datagram(wtf_session* session, const uint8_t* data, size_t length);
bool wtf_session_process_capsule(wtf_session* session, const wtf_capsule* capsule);
wtf_session* wtf_session_create(wtf_connection* conn, wtf_http3_stream* connect_stream);

#ifdef __cplusplus
}
#endif
#endif  // WTF_SESSION_H
