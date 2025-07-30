#ifndef WTF_CONN_H
#define WTF_CONN_H
#include "types.h"
#ifdef __cplusplus
extern "C" {
#endif

QUIC_CONNECTION_CALLBACK wtf_connection_callback;

wtf_connection* wtf_connection_create(wtf_server* server, HQUIC quic_connection);
void wtf_connection_destroy(wtf_connection* conn);
wtf_session* wtf_connection_find_session(wtf_connection* conn, uint64_t session_id);

void wtf_connection_process_buffered_data(wtf_connection* conn, wtf_session* session);

bool wtf_connection_associate_stream_with_session(wtf_connection* conn, wtf_http3_stream* h3_stream,
                                                  wtf_session* session);

#ifdef __cplusplus
}
#endif
#endif  // WTF_CONN_H
