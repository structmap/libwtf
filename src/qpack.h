#ifndef WTF_QPACK_H
#define WTF_QPACK_H

#include "lsqpack.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif


bool wtf_qpack_preinit(wtf_qpack_context* ctx, uint32_t max_table_capacity,
                       uint32_t max_blocked_streams);
void wtf_qpack_cleanup(wtf_qpack_context* qpack);

bool wtf_qpack_init_encoder(wtf_context* ctx, wtf_qpack_context* qpack);

bool wtf_qpack_process_decoder(wtf_context* ctx, wtf_qpack_context* qpack, const uint8_t* data,
                               size_t length);

bool wtf_qpack_process_encoder(wtf_context* ctx, wtf_qpack_context* qpack, const uint8_t* data,
                               size_t length);

wtf_result_t wtf_qpack_send_encoder_data(wtf_connection* conn);

wtf_result_t wtf_qpack_parse_connect_headers(wtf_context* ctx, wtf_http3_stream* stream,
                                             const uint8_t* data, size_t data_len,
                                             wtf_connect_request* request);


#ifdef __cplusplus
}
#endif
#endif  // WTF_QPACK_H
