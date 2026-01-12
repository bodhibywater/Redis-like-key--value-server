// protocol.c
//
// Implements framing and (de)serialization for the custom binary protocol.
//
// Design choices:
// - Big-endian u32 fields (network order) for portability.
// - Decoder is zero-copy with respect to argument bytes:
//     ProtoReq.argv[i].ptr points into the caller-provided payload buffer.
//   This is fast, but requires the caller to process the request before
//   shifting/reusing the underlying input buffer.
//
// Safety / validation:
// - Frame helper validates the outer length against max_payload_len.
// - Request decode validates argc <= max_args and that payload is consumed exactly.
// - Multi-bulk encoder checks for u32 overflow when summing item lengths.
#include "protocol.h"

#include <stdlib.h>
#include <string.h>

/* ---- endian helpers (u32 big-endian) ---- */

// Read u32be from [*cur, end). Advances *cur by 4 on success.
static bool rd_u32be(const uint8_t **cur, const uint8_t *end, uint32_t *out) {
    if ((size_t)(end - *cur) < 4) return false;
    const uint8_t *p = *cur;
    *out = ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           ((uint32_t)p[3]);
    *cur += 4;
    return true;
}

// Write u32be to dst (dst must have space for 4 bytes).
static void wr_u32be(uint8_t *dst, uint32_t v) {
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)(v);
}

// Peek the outer payload length without requiring a full frame.
// Returns false if fewer than 4 bytes are available.
bool proto_frame_peek_len(const uint8_t *buf, size_t used, uint32_t *out_payload_len) {
    if (used < 4) return false;
    *out_payload_len = ((uint32_t)buf[0] << 24) |
                       ((uint32_t)buf[1] << 16) |
                       ((uint32_t)buf[2] << 8)  |
                       ((uint32_t)buf[3]);
    return true;
}

// Validate whether buf[0..used) contains a complete frame.
//
// Returns true and sets *out_frame_bytes = 4 + payload_len if:
// - the 4-byte outer length is present,
// - payload_len <= max_payload_len,
// - and used contains the entire payload.
//
// Returns false for incomplete frames *or* for invalid/oversized lengths.
// Callers that want to distinguish oversize should peek length first.
bool proto_frame_ready(const uint8_t *buf, size_t used, uint32_t max_payload_len, size_t *out_frame_bytes) {
    uint32_t payload_len = 0;
    if (!proto_frame_peek_len(buf, used, &payload_len)) return false;
    if (payload_len > max_payload_len) return false;
    size_t need = 4u + (size_t)payload_len;
    if (used < need) return false;
    *out_frame_bytes = need;
    return true;
}

// Decode request payload (bytes after the outer u32 length).
//
// Output / ownership:
// - out->argv is allocated and owned by the caller (free with proto_req_free).
// - argv[i].ptr points into `payload` (non-owning); `payload` must remain valid
//   until the server finishes processing the request.
//
// Validation:
// - argc must be present and <= max_args.
// - each argument length must fit within payload bounds.
// - payload must be consumed exactly (no trailing bytes).
bool proto_req_decode(ProtoReq *out, const uint8_t *payload, size_t payload_len, uint32_t max_args) {
    out->argc = 0;
    out->argv = NULL;

    const uint8_t *cur = payload;
    const uint8_t *end = payload + payload_len;

    uint32_t argc = 0;
    if (!rd_u32be(&cur, end, &argc)) return false;
    if (argc > max_args) return false;

    // Allocate argv spans
    PSpan *argv = NULL;
    if (argc > 0) {
        argv = (PSpan *)calloc(argc, sizeof(PSpan));
        if (!argv) return false;
    }

    for (uint32_t i = 0; i < argc; i++) {
        uint32_t slen = 0;
        if (!rd_u32be(&cur, end, &slen)) { free(argv); return false; }
        if ((size_t)(end - cur) < (size_t)slen) { free(argv); return false; }

        argv[i].ptr = cur;
        argv[i].len = slen;
        cur += slen;
    }

    // Reject trailing bytes: keeps the encoding canonical and simplifies callers.
    // Must consume exactly the payload
    if (cur != end) {
        free(argv);
        return false;
    }

    out->argc = argc;
    out->argv = argv;
    return true;
}

// Free only the argv array. Argument bytes are not owned by ProtoReq.
void proto_req_free(ProtoReq *r) {
    free(r->argv);
    r->argv = NULL;
    r->argc = 0;
}

// Allocate an owned message buffer of size n (bytes).
static bool msg_alloc(ProtoMsg *m, size_t n) {
    m->buf = (uint8_t *)malloc(n);
    if (!m->buf) {
        m->len = 0;
        return false;
    }
    m->len = n;
    return true;
}

// Encode a response into a fully-framed message:
//   [u32 payload_len_be][u32 status_be][u32 dlen_be][dlen bytes]
//
// `data` may be NULL if dlen == 0.
// On success, out owns the allocated buffer (free with proto_msg_free).
bool proto_res_encode(ProtoMsg *out, uint32_t status, const void *data, uint32_t dlen) {
    // payload: status(4) + dlen(4) + data
    uint32_t payload_len = 8u + dlen;
    size_t total = 4u + (size_t)payload_len;

    if (!msg_alloc(out, total)) return false;

    wr_u32be(out->buf + 0, payload_len);
    wr_u32be(out->buf + 4, status);
    wr_u32be(out->buf + 8, dlen);
    if (dlen > 0) {
        memcpy(out->buf + 12, data, dlen);
    }
    return true;
}

// Convenience wrapper: encode a NUL-terminated C string as response data.
bool proto_res_encode_str(ProtoMsg *out, uint32_t status, const char *s) {
    const uint8_t *p = (const uint8_t *)s;
    uint32_t dlen = (uint32_t)strlen(s);
    return proto_res_encode(out, status, p, dlen);
}

// Encode a multi-bulk response where the data section is:
//   [u32 count_be] repeated: [u32 item_len_be][item bytes]
//
// Overflow guard:
// - Uses uint64 accumulation and rejects if total data length exceeds u32 range.
bool proto_res_encode_multibulk(ProtoMsg *out, uint32_t status,
                                uint32_t count,
                                const uint8_t *const items[],
                                const uint32_t lens[]) {
    // payload data = [u32 count] + sum([u32 len] + bytes)
    uint64_t data_len64 = 4;
    for (uint32_t i = 0; i < count; i++) {
        data_len64 += 4u + (uint64_t)lens[i];
    }
    if (data_len64 > UINT32_MAX) return false;

    uint32_t dlen = (uint32_t)data_len64;

    uint32_t payload_len = 8u + dlen;
    size_t total = 4u + (size_t)payload_len;

    if (!msg_alloc(out, total)) return false;

    wr_u32be(out->buf + 0, payload_len);
    wr_u32be(out->buf + 4, status);
    wr_u32be(out->buf + 8, dlen);

    uint8_t *w = out->buf + 12;
    wr_u32be(w, count);
    w += 4;

    for (uint32_t i = 0; i < count; i++) {
        wr_u32be(w, lens[i]);
        w += 4;
        if (lens[i] > 0) {
            memcpy(w, items[i], lens[i]);
            w += lens[i];
        }
    }
    return true;
}

// Free an owned encoded message buffer.
void proto_msg_free(ProtoMsg *m) {
    free(m->buf);
    m->buf = NULL;
    m->len = 0;
}
