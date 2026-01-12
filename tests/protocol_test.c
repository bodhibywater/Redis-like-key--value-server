#include "protocol.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

// Build a request payload like client.c would (payload only, not framed).
static void build_payload_set(uint8_t *buf, size_t *out_len) {
    // argc=3, ["set","foo","bar"]
    uint8_t *p = buf;

    // argc
    p[0]=0; p[1]=0; p[2]=0; p[3]=3; p += 4;

    // "set"
    p[0]=0; p[1]=0; p[2]=0; p[3]=3; p += 4;
    memcpy(p, "set", 3); p += 3;

    // "foo"
    p[0]=0; p[1]=0; p[2]=0; p[3]=3; p += 4;
    memcpy(p, "foo", 3); p += 3;

    // "bar"
    p[0]=0; p[1]=0; p[2]=0; p[3]=3; p += 4;
    memcpy(p, "bar", 3); p += 3;

    *out_len = (size_t)(p - buf);
}

int main(void) {
    uint8_t payload[128];
    size_t payload_len = 0;
    build_payload_set(payload, &payload_len);

    ProtoReq r;
    bool ok = proto_req_decode(&r, payload, payload_len, 1024);
    assert(ok);
    assert(r.argc == 3);
    assert(r.argv[0].len == 3 && memcmp(r.argv[0].ptr, "set", 3) == 0);
    assert(r.argv[1].len == 3 && memcmp(r.argv[1].ptr, "foo", 3) == 0);
    assert(r.argv[2].len == 3 && memcmp(r.argv[2].ptr, "bar", 3) == 0);
    proto_req_free(&r);

    // Response encode: OK "hi"
    ProtoMsg msg;
    ok = proto_res_encode_str(&msg, RES_OK, "hi");
    assert(ok);
    assert(msg.len == 4 + 8 + 2);
    proto_msg_free(&msg);

    // Multi-bulk encode: ["a","bb"]
    const uint8_t *items[2] = {(const uint8_t *)"a", (const uint8_t *)"bb"};
    const uint32_t lens[2] = {1, 2};
    ok = proto_res_encode_multibulk(&msg, RES_OK, 2, items, lens);
    assert(ok);
    proto_msg_free(&msg);

    puts("protocol_test: OK");
    return 0;
}
