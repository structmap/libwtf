#ifndef WTF_STREAM_H
#define WTF_STREAM_H
#include "types.h"
#ifdef __cplusplus
extern "C" {
#endif

QUIC_STREAM_CALLBACK wtf_upgraded_stream_callback;

bool wtf_stream_belongs_to_session(uint64_t stream_id, uint64_t session_id,
                                   const uint8_t* stream_data, size_t data_len);


wtf_stream* wtf_stream_create(wtf_session* session, uint64_t stream_id, wtf_stream_type_t type);

void wtf_stream_destroy(wtf_stream* stream);

#ifdef __cplusplus
}
#endif
#endif  // WTF_STREAM_H
