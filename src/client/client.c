// client.c
//
// Minimal blocking CLI client for the server's binary framing protocol.
//
// Scope / assumptions:
// - Connects to 127.0.0.1:1234 (hard-coded).
// - Uses blocking I/O and read_all/write_all helpers to transfer full frames.
// - Intended for demos/tests, not production robustness (no timeouts/retries).
//
// Message framing (outer):
//   [u32 payload_len_be][payload bytes...]
//
// Request payload:
//   [u32 argc_be] repeated: [u32 arg_len_be][arg bytes...]
//
// Response payload:
//   [u32 status_be][u32 data_len_be][data bytes...]
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Fatal error helper.
// Prints errno and message to stderr, then aborts the process.
static void fatal(const char *msg) {
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

// Read exactly n bytes into buffer (blocking).
//
// Returns 0 on success, -1 on EOF/error.
// Note: this implementation treats any r<=0 as failure and does not retry on EINTR.
static int32_t read_all(int sock, char *buffer, size_t n) {
    while (n > 0) {
        ssize_t r = read(sock, buffer, n);
        if (r <= 0) {
        return -1;
        }
        n -= (size_t) r;
    buffer += r;
    }
    return 0;
}

// Write exactly n bytes from buffer (blocking).
//
// Returns 0 on success, -1 on error.
// Note: this implementation treats any r<=0 as failure and does not retry on EINTR.
static int32_t write_all(int sock, char *buffer, size_t n) {
    while (n > 0) {
        ssize_t r = write(sock, buffer, n);
        if (r <= 0) {
            return -1;
        }
        n -= (size_t) r;
        buffer += r;
    }
    return 0;
}

// Max payload size (bytes) accepted/sent by this client.
// This is independent of the server's larger frame limits.
const size_t max_msg = 4096;

// Encode argv[] into one request frame and send it.
//
// Contract:
// - cmd[i] are NUL-terminated C strings; lengths are computed with strlen().
// - Frame format matches server protocol (u32 big-endian lengths).
//
// Guardrails:
// - Rejects messages whose payload_len would exceed max_msg.
static int32_t send_req(int sock, char **cmd, int cmd_count) {
    // Compute payload length:
    // - 4 bytes for argc
    // - for each arg: 4 bytes length + arg bytes
    uint32_t len = 4;
    for (int i = 0; i < cmd_count; i++) { // post increment
        len += 4 + strlen(cmd[i]);
    }

    // Client-side hard cap on payload size.
    if (len > max_msg) {
        return -1;
    }
    // Allocate a buffer large enough for the full frame (outer length + payload).
    // (Current allocation uses 4+max_msg and writes only 4+len bytes.)
    char *wbuf = malloc(4 + max_msg);
    if (!wbuf) fatal("malloc");

    // Write outer payload length (big-endian).
    uint32_t len_net = htonl(len);
    memcpy(wbuf, &len_net, 4);
    
    // Write argc (big-endian) at start of payload.
    uint32_t n_net = htonl((uint32_t)cmd_count);
    memcpy(wbuf + 4, &n_net, 4);

    size_t cur = 8;
    // Encode each argument as: [u32 arg_len_be][arg bytes...]
    for (int i = 0; i < cmd_count; ++i) {
        uint32_t p = (uint32_t)strlen(cmd[i]);
        uint32_t p_net = htonl(p);

        // Write arg length.
        memcpy(wbuf + cur, &p_net, 4);

        // Write arg bytes
        memcpy(wbuf + cur + 4, cmd[i], p);
        cur += 4 + p;
    }

    // Send the full frame: 4-byte outer header + payload_len bytes.
    int32_t rv = write_all(sock, wbuf, 4 + len);

    free(wbuf);
    return rv;
}

// Read and decode a single response frame and print it.
//
// Validation:
// - Reads outer u32 length, then reads exactly that many payload bytes.
// - Checks payload contains at least [status][dlen] and that dlen fits in the payload.
//
// Printing:
// - Always prints "server says: [<status>] ..."
// - Attempts to recognize "multi-bulk" (ZRANGE) responses by validating that `data`
//   exactly matches: [count][len][bytes]... with no trailing bytes.
//   If validation fails, prints data as a single byte string.
static int32_t read_res(int sock) {
    enum { HDR_LEN = 4, STATUS_LEN = 4, DLEN_LEN = 4 };

    // Stack buffer sized for [outer length] + max_msg payload.
    static const size_t MAX_BUF = HDR_LEN + max_msg;
    uint8_t  rbuf[MAX_BUF];

    uint32_t netlen, len;

    // Read outer payload length (4 bytes)
    if (read_all(sock, (char*)rbuf, HDR_LEN) < 0) {
        perror("read length");
        return -1;
    }
    memcpy(&netlen, rbuf, HDR_LEN);
    len = ntohl(netlen);

    // Payload must contain at least status + dlen, and must fit client max.
    if (len < STATUS_LEN + DLEN_LEN || len > max_msg) {
        fprintf(stderr, "invalid response length %u\n", len);
        return -1;
    }

    // Read payload (len bytes)
    if (read_all(sock, (char*)rbuf + HDR_LEN, len) < 0) {
        perror("read payload");
        return -1;
    }

    // Decode status
    uint32_t netstatus, status;
    memcpy(&netstatus, rbuf + HDR_LEN, STATUS_LEN);
    status = ntohl(netstatus);

    // Decode data_len
    uint32_t netdlen, dlen;
    memcpy(&netdlen, rbuf + HDR_LEN + STATUS_LEN, DLEN_LEN);
    dlen = ntohl(netdlen);

    // Validate that dlen fits inside the payload we read.
    if (dlen > len - (STATUS_LEN + DLEN_LEN)) {
        fprintf(stderr, "invalid data length %u\n", dlen);
        return -1;
    }

    // Pointer to the "data" bytes section of the payload.
    uint8_t *payload = rbuf + HDR_LEN + STATUS_LEN + DLEN_LEN;

    // Heuristic: treat data as multi-bulk only if it parses cleanly and consumes exactly dlen bytes.
    bool is_multi = false;
    uint32_t count = 0;
    if (dlen >= 4) {
        uint32_t netcount;
        memcpy(&netcount, payload, 4);
        count = ntohl(netcount);

        // expected tracks total bytes consumed from payload.
        size_t expected = 4;
        uint8_t *p = payload + 4;

        bool ok = true;

        for (uint32_t i = 0; i < count; i++) {
            // Need at least 4 bytes for item_len.
            if ((size_t)(p - payload) + 4 > dlen) { ok = false; break; }
            uint32_t netel, elen;

            memcpy(&netel, p, 4);
            elen = ntohl(netel);

            // Need item_len + item bytes to fit within dlen.
            if ((size_t)(p - payload) + 4 + elen > dlen) { ok = false; break; }

            // Skip over [len][bytes].
            p += 4 + elen;
            expected += 4 + elen;
        }

        // Accept multi-bulk only if we consumed exactly dlen bytes.
        if (ok && expected == dlen) {
            is_multi = true;
        }
    }

    // Status is always printed; data is printed either as multi-bulk items or as one string.
    printf("server says: [%u]", status);
    if (is_multi) {
        // Walk again and print items as strings.
        uint8_t *p = payload + 4;
        for (uint32_t i = 0; i < count; i++) {
            uint32_t netel, elen;
            memcpy(&netel, p, 4);
            elen = ntohl(netel);
            p += 4;

            // Print exactly elen bytes
            printf(" %.*s", elen, p);
            p += elen;
        }
        printf("\n");
    } else {
        // Non multi-bulk: print data as a single byte string.
        if (dlen > 0) {
            printf(" %.*s\n", dlen, payload);
        } else {
            printf("\n");
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    // Open TCP socket (blocking).
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fatal("socket()");
    }

    // Connect to loopback server (hard-coded to 127.0.0.1:1234).
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int r = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (r) fatal("connect");

    // Prepare command argv (everything after program name).
    // cmd is just a shallow array of pointers into argv[].
    int cmd_count = argc - 1;
    char **cmd = NULL;
    if (cmd_count > 0) {
        cmd = malloc(cmd_count * sizeof(char *));
        if (!cmd) fatal("malloc");

        for (int i = 0; i < cmd_count; ++i) {
            cmd[i] = argv[i + 1];
        }
    }

    // Send one request frame and read one response frame, then exit.
    int32_t err = send_req(fd, cmd, cmd_count);
    
    if (!err) err = read_res(fd);
    if (cmd) free(cmd);

    close(fd);
    return 0;
}