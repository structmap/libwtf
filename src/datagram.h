#ifndef WTF_DATAGRAM_H
#define WTF_DATAGRAM_H
#include "types.h"
#ifdef __cplusplus
extern "C" {
#endif

wtf_datagram* wtf_datagram_create(const uint8_t* data, size_t length, uint64_t session_id,
                                  void* send_context);

void wtf_datagram_destroy(wtf_datagram* dgram);

void wtf_datagram_process(wtf_connection* conn, const uint8_t* data, size_t data_len,
                          bool is_client_initiated);


#ifdef __cplusplus
}
#endif
#endif  // WTF_DATAGRAM_H
