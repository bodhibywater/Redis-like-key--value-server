// protocol.h
//
// Binary, length-prefixed framing protocol used by client/server.
//
// Outer frame:
//   [u32 payload_len_be][payload bytes...]
//
// Requests payload:
//   [u32 argc_be] repeated argc times: [u32 arg_len_be][arg bytes...]
//
// Responses payload:
//   [u32 status_be][u32 data_len_be][data bytes...]
//
// Notes / invariants:
// - All integer fields are unsigned 32-bit big-endian (network byte order).
// - "bytes" fields are raw bytes (not null-terminated).
// - Decoder returns spans pointing into the caller's payload buffer; the caller
//   must not mutate/free that buffer until the request is fully processed.

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Response status codes (part of the response payload).
enum {
    RES_OK  = 0,
    RES_ERR = 1,
    RES_NX  = 2,
};

// Non-owning byte span (view into an existing buffer).
typedef struct {
    const uint8_t *ptr;
    uint32_t       len;
} PSpan;

// Decoded request arguments.
// - argv is heap-allocated and owned by ProtoReq (free with proto_req_free).
// - argv[i].ptr points into the caller-supplied payload buffer (non-owning).
typedef struct {
    uint32_t argc;
    PSpan   *argv;
} ProtoReq;

// Owned, fully-framed message ready to write() to a socket.
typedef struct {
    uint8_t *buf;
    size_t   len;
} ProtoMsg;

/* ---- Frame helpers (outer u32 length) ---- */
// Peek outer payload length if at least 4 bytes are available.
bool proto_frame_peek_len(const uint8_t *buf, size_t used, uint32_t *out_payload_len);

// Validate that a complete frame exists in buf (used bytes). If so, returns total frame bytes (4+payload_len).
bool proto_frame_ready(const uint8_t *buf, size_t used, uint32_t max_payload_len, size_t *out_frame_bytes);

/* ---- Request decode (payload only: bytes after outer u32 length) ---- */
bool proto_req_decode(ProtoReq *out, const uint8_t *payload, size_t payload_len, uint32_t max_args);
void proto_req_free(ProtoReq *r);

/* ---- Response encode (produces a full framed message incl. outer length) ---- */
bool proto_res_encode(ProtoMsg *out, uint32_t status, const void *data, uint32_t dlen);
bool proto_res_encode_str(ProtoMsg *out, uint32_t status, const char *s);

// Multi-bulk data encoding (used by ZRANGE):
//   data = [u32 count_be] repeated count times: [u32 item_len_be][item bytes...]
bool proto_res_encode_multibulk(ProtoMsg *out, uint32_t status,
                                uint32_t count,
                                const uint8_t *const items[],
                                const uint32_t lens[]);
void proto_msg_free(ProtoMsg *m);

#endif
