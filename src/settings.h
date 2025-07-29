#ifndef WTF_SETTINGS_H
#define WTF_SETTINGS_H
#include "types.h"
#ifdef __cplusplus
extern "C" {
#endif
void wtf_settings_init(wtf_settings* settings);
bool wtf_settings_decode_frame(wtf_connection* conn, const uint8_t* data, size_t data_len);

bool wtf_settings_send(wtf_connection* conn);
bool wtf_settings_encode_frame(wtf_connection* conn, uint8_t* buffer, size_t buffer_size,
                               size_t* frame_length);
#ifdef __cplusplus
}
#endif
#endif  // WTF_SETTINGS_H
