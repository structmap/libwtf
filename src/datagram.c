#include "datagram.h"

#include "conn.h"
#include "log.h"
#include "session.h"
#include "varint.h"

wtf_datagram* wtf_datagram_create(const uint8_t* data, size_t length, uint64_t session_id,
                                  void* send_context)
{
    wtf_datagram* dgram = malloc(sizeof(wtf_datagram));
    if (!dgram) {
        return NULL;
    }

    dgram->data = malloc(length);
    if (!dgram->data) {
        free(dgram);
        return NULL;
    }

    memcpy(dgram->data, data, length);
    dgram->length = length;
    dgram->session_id = session_id;
    dgram->send_context = send_context;
    dgram->next = NULL;

    return dgram;
}

void wtf_datagram_destroy(wtf_datagram* dgram)
{
    if (dgram) {
        if (dgram->data) {
            free(dgram->data);
        }
        free(dgram);
    }
}

static bool wtf_validate_stream_id(uint64_t stream_id, bool is_client_initiated)
{
    bool client_initiated = WTF_STREAM_IS_CLIENT_INITIATED(stream_id);
    return client_initiated == is_client_initiated;
}

void wtf_datagram_process(wtf_connection* conn, const uint8_t* data, size_t data_len,
                          bool is_client_initiated)
{
    if (!conn || !data || data_len == 0)
        return;

    size_t offset = 0;
    uint64_t quarter_stream_id;

    if (!wtf_varint_decode(data_len, data, &offset, &quarter_stream_id)) {
        WTF_LOG_TRACE(conn->server->context, "datagram", "Failed to decode Quarter Stream ID");
        return;
    }

    uint64_t stream_id = quarter_stream_id * 4;

    if (!wtf_validate_stream_id(stream_id, is_client_initiated)) {
        WTF_LOG_WARN(conn->server->context, "datagram",
                     "Invalid stream ID %llu from Quarter Stream ID %llu",
                     (unsigned long long)stream_id, (unsigned long long)quarter_stream_id);
        return;
    }
    wtf_session* session = wtf_connection_find_session(conn, stream_id);
    if (!session) {
        mtx_lock(&conn->buffered_mutex);

        if (conn->buffered_datagram_count >= WTF_MAX_BUFFERED_DATAGRAMS) {
            mtx_unlock(&conn->buffered_mutex);
            WTF_LOG_WARN(conn->server->context, "datagram", "Dropping datagram - buffer full");
            return;
        }

        wtf_datagram* dgram = wtf_datagram_create(data + offset, data_len - offset, stream_id,
                                                  NULL);
        if (dgram) {
            if (conn->buffered_datagrams) {
                wtf_datagram* tail = conn->buffered_datagrams;
                while (tail->next)
                    tail = tail->next;
                tail->next = dgram;
            } else {
                conn->buffered_datagrams = dgram;
            }
            conn->buffered_datagram_count++;
        }

        mtx_unlock(&conn->buffered_mutex);

        WTF_LOG_TRACE(conn->server->context, "datagram", "Buffered datagram for session %llu",
                      (unsigned long long)stream_id);
        return;
    }

    const uint8_t* payload = data + offset;
    size_t payload_len = data_len - offset;
    wtf_session_process_datagram(session, payload, payload_len);
}
