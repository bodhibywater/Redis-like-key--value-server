#define _POSIX_C_SOURCE 200809L
#include "protocol.h"

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

enum { MAX_MSG = (1u << 20) + 4096 };
enum { TEST_MAX_PAYLOAD = 1u << 20 }; // must match server's MAX_PAYLOAD
enum { TEST_MAX_INBUF  = 4u << 20 };  // must match server MAX_INBUF
enum { TEST_MAX_OUTBUF = 4u << 20 };  // must match server MAX_OUTBUF


static void die(const char *msg) {
    perror(msg);
    exit(2);
}

static void sleep_ms(long ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000 * 1000;
    nanosleep(&ts, NULL);
}

static int32_t read_all(int fd, void *buf, size_t n) {
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        ssize_t r = read(fd, p, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return -1;
        p += (size_t)r;
        n -= (size_t)r;
    }
    return 0;
}

static int32_t write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t r = write(fd, p, n);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)r;
        n -= (size_t)r;
    }
    return 0;
}

static bool write_all_soft(int fd, const void *buf, size_t n) {
    const uint8_t *p = (const uint8_t *)buf;
    while (n > 0) {
        ssize_t r = write(fd, p, n);
        if (r > 0) {
            p += (size_t)r;
            n -= (size_t)r;
            continue;
        }
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EPIPE || errno == ECONNRESET) return false;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct timespec ts = {0};
                ts.tv_nsec = 5 * 1000 * 1000; // 5ms
                nanosleep(&ts, NULL);
                continue;
            }
            die("write");
        }
    }
    return true;
}

static bool send_cmd_soft(int sock, int argc, const char **argv) {
    uint32_t len = 4; // argc field
    for (int i = 0; i < argc; i++) {
        len += 4 + (uint32_t)strlen(argv[i]);
    }

    uint8_t *w = (uint8_t *)malloc(4u + len);
    assert(w);

    uint32_t len_net = htonl(len);
    memcpy(w, &len_net, 4);

    uint32_t argc_net = htonl((uint32_t)argc);
    memcpy(w + 4, &argc_net, 4);

    size_t cur = 8;
    for (int i = 0; i < argc; i++) {
        uint32_t alen = (uint32_t)strlen(argv[i]);
        uint32_t alen_net = htonl(alen);
        memcpy(w + cur, &alen_net, 4);
        memcpy(w + cur + 4, argv[i], alen);
        cur += 4 + alen;
    }
    assert(cur == 4u + len);

    bool ok = write_all_soft(sock, w, 4u + len);
    free(w);
    return ok;
}


// Encode request exactly like client.c:
// [u32 len][u32 argc][u32 arglen][bytes]...
static void send_cmd(int sock, int argc, const char **argv) {
    uint32_t len = 4; // argc field
    for (int i = 0; i < argc; i++) {
        len += 4 + (uint32_t)strlen(argv[i]);
    }

    uint8_t *w = (uint8_t *)malloc(4u + len);
    assert(w);

    uint32_t len_net = htonl(len);
    memcpy(w, &len_net, 4);

    uint32_t argc_net = htonl((uint32_t)argc);
    memcpy(w + 4, &argc_net, 4);

    size_t cur = 8;
    for (int i = 0; i < argc; i++) {
        uint32_t alen = (uint32_t)strlen(argv[i]);
        uint32_t alen_net = htonl(alen);
        memcpy(w + cur, &alen_net, 4);
        memcpy(w + cur + 4, argv[i], alen);
        cur += 4 + alen;
    }
    assert(cur == 4u + len);

    if (write_all(sock, w, 4u + len) < 0) die("write_all");
    free(w);
}

typedef struct {
    uint32_t status;
    uint32_t dlen;
    uint8_t *data; // malloc'd
} Resp;

static Resp read_resp(int sock) {
    Resp r = {0};

    uint32_t netlen = 0;
    if (read_all(sock, &netlen, 4) < 0) die("read_all len");
    uint32_t len = ntohl(netlen);
    if (len > MAX_MSG) {
        fprintf(stderr, "invalid response length %u\n", len);
        exit(2);
    }

    uint8_t *buf = (uint8_t *)malloc(len);
    assert(buf);

    if (read_all(sock, buf, len) < 0) die("read_all payload");

    uint32_t netstatus = 0, netdlen = 0;
    memcpy(&netstatus, buf + 0, 4);
    memcpy(&netdlen,   buf + 4, 4);

    r.status = ntohl(netstatus);
    r.dlen   = ntohl(netdlen);

    assert(8u + r.dlen == len);

    r.data = (uint8_t *)malloc(r.dlen);
    assert(r.data);
    memcpy(r.data, buf + 8, r.dlen);

    free(buf);
    return r;
}

static void resp_free(Resp *r) {
    free(r->data);
    r->data = NULL;
    r->dlen = 0;
}

static void expect_ok_str(int sock, const char *s) {
    Resp r = read_resp(sock);
    assert(r.status == RES_OK);
    assert(r.dlen == strlen(s));
    assert(memcmp(r.data, s, r.dlen) == 0);
    resp_free(&r);
}

static void expect_nx(int sock) {
    Resp r = read_resp(sock);
    assert(r.status == RES_NX);
    assert(r.dlen == 0);
    resp_free(&r);
}

static void expect_err_str(int sock, const char *s) {
    Resp r = read_resp(sock);
    assert(r.status == RES_ERR);
    assert(r.dlen == strlen(s));
    assert(memcmp(r.data, s, r.dlen) == 0);
    resp_free(&r);
}

// Expects multibulk payload: [u32 count][u32 len][bytes]...
static void expect_ok_multibulk(int sock, const char **expect, uint32_t count) {
    Resp r = read_resp(sock);
    assert(r.status == RES_OK);
    assert(r.dlen >= 4);

    uint32_t netcount = 0;
    memcpy(&netcount, r.data, 4);
    uint32_t got = ntohl(netcount);
    assert(got == count);

    if (count > 0) assert(expect != NULL);

    uint8_t *p = r.data + 4;
    uint8_t *end = r.data + r.dlen;

    for (uint32_t i = 0; i < count; i++) {
        assert(p + 4 <= end);
        uint32_t netlen = 0;
        memcpy(&netlen, p, 4);
        uint32_t elen = ntohl(netlen);
        p += 4;

        assert(p + elen <= end);

        size_t explen = strlen(expect[i]);
        assert(elen == explen);
        assert(memcmp(p, expect[i], explen) == 0);

        p += elen;
    }
    assert(p == end);

    resp_free(&r);
}

static void expect_closed_soon(int sock) {
    // In the MAX_OUTBUF case, the server may send a lot of bytes before closing.
    // Drain aggressively until we observe close/reset, but fail if it keeps sending
    // beyond a reasonable bound (suggests cap isn't enforced).
    uint8_t buf[65536];

    size_t drained = 0;
    const size_t DRAIN_LIMIT = (size_t)TEST_MAX_OUTBUF + (2u << 20); // 4MiB + 2MiB slack

    // retry ~1s total (200 * 5ms)
    for (int i = 0; i < 200; i++) {
        ssize_t n = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);

        if (n == 0) return; // clean close

        if (n > 0) {
            drained += (size_t)n;
            if (drained > DRAIN_LIMIT) {
                assert(!"drained too much data without observing close (cap likely not enforced)");
            }
            continue; // keep draining
        }

        // n < 0
        if (errno == EINTR) continue;

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 5 * 1000 * 1000; // 5ms
            nanosleep(&ts, NULL);
            continue;
        }

        if (errno == ECONNRESET || errno == EPIPE) return; // reset/pipe => also fine

        die("recv");
    }

    assert(!"server did not close connection quickly");
}

static int connect_retry(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) die("socket");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    // retry ~200ms total
    for (int i = 0; i < 40; i++) {
        if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) == 0) return fd;

        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 5 * 1000 * 1000; // 5ms
        nanosleep(&ts, NULL);
    }

    close(fd);
    return -1;
}

static void expect_server_exits_on_sigint(pid_t pid) {
    if (kill(pid, SIGINT) < 0) die("kill(SIGINT)");

    int st = 0;
    if (waitpid(pid, &st, 0) < 0) die("waitpid");

    assert(WIFEXITED(st));
    assert(WEXITSTATUS(st) == 0);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    int port = 20000 + (getpid() % 20000);

    pid_t pid = fork();
    if (pid < 0) die("fork");

    if (pid == 0) {
        char port_s[16];
        snprintf(port_s, sizeof(port_s), "%d", port);
        execl("./server", "./server", port_s, "200", (char *)NULL);
        die("execl");
    }

    int sock = connect_retry(port);
    if (sock < 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        fprintf(stderr, "failed to connect to server on port %d\n", port);
        return 2;
    }

    // Oversize frame (only length prefix) => server should drop connection quickly.
    {
        int sock2 = connect_retry(port);
        assert(sock2 >= 0);
        uint32_t bad_len = htonl(TEST_MAX_PAYLOAD + 1u);
        if (write_all(sock2, &bad_len, 4) < 0) die("write_all oversize");
        expect_closed_soon(sock2);
        close(sock2);
    }

    // MAX_INBUF abuse: send junk until server drops connection.
    {
        int sock3 = connect_retry(port);
        assert(sock3 >= 0);
        uint8_t junk[4096];
        memset(junk, 'A', sizeof(junk));
        size_t sent = 0;
        size_t target = (size_t)TEST_MAX_INBUF + 64 * 1024; // a bit past the cap
        while (sent < target) {
            if (!write_all_soft(sock3, junk, sizeof(junk))) break; // server already dropped
            sent += sizeof(junk);
        }
        expect_closed_soon(sock3);
        close(sock3);
    }

    // MAX_OUTBUF abuse: create a large value, then pipeline many GETs without reading replies.
    {
        int sock4 = connect_retry(port);
        assert(sock4 >= 0);
        // create a big value safely under request MAX_PAYLOAD (1 MiB).
        const size_t vlen = 900u * 1024u; // 900 KiB
        char *val = (char *)malloc(vlen + 1);
        assert(val);
        memset(val, 'x', vlen);
        val[vlen] = '\0';
        const char *setcmd[] = {"set", "big", val};
        send_cmd(sock4, 3, setcmd);
        expect_ok_str(sock4, "OK");
        // Now spam GET big without reading responses.
        const char *getcmd[] = {"get", "big"};
        for (int i = 0; i < 16; i++) {
            if (!send_cmd_soft(sock4, 2, getcmd)) break; // dropped during writes
        }
        // We expect the server to drop due to output buffer cap.
        expect_closed_soon(sock4);
        close(sock4);
        free(val);
    }

    // --- Contract checks (Redis-like semantics) ---

    // GET missing => NX
    { const char *cmd[] = {"get","nope"}; send_cmd(sock, 2, cmd); expect_nx(sock); }

    // ZSCORE missing => NX
    { const char *cmd[] = {"zscore","nope","m"}; send_cmd(sock, 3, cmd); expect_nx(sock); }

    // ZRANGE missing => OK empty multibulk
    {
        const char *cmd[] = {"zrange","nope","0","-1"};
        send_cmd(sock, 4, cmd);
        expect_ok_multibulk(sock, NULL, 0);
    }

    // Parse errors => ERR "bad request"
    { const char *cmd[] = {"zadd","k","nope","a"}; send_cmd(sock, 4, cmd); expect_err_str(sock, "bad request"); }
    { const char *cmd[] = {"zrange","k","a","b"}; send_cmd(sock, 4, cmd); expect_err_str(sock, "bad request"); }

    // Wrong type => ERR "wrong type"
    { const char *cmd[] = {"set","s","v"}; send_cmd(sock, 3, cmd); expect_ok_str(sock, "OK"); }
    { const char *cmd[] = {"zadd","s","1","a"}; send_cmd(sock, 4, cmd); expect_err_str(sock, "wrong type"); }

    // --- Setup zset for WITHSCORES test ---
    { const char *cmd[] = {"zadd","k","1","a"}; send_cmd(sock, 4, cmd); expect_ok_str(sock, "1"); }
    { const char *cmd[] = {"zadd","k","1","b"}; send_cmd(sock, 4, cmd); expect_ok_str(sock, "1"); }
    { const char *cmd[] = {"zadd","k","0.5","x"}; send_cmd(sock, 4, cmd); expect_ok_str(sock, "1"); }
    { const char *cmd[] = {"zadd","k","2","y"}; send_cmd(sock, 4, cmd); expect_ok_str(sock, "1"); }

    // Assert: zrange k 0 -1 withscores => x 0.5 a 1 b 1 y 2
    {
        const char *cmd[] = {"zrange","k","0","-1","withscores"};
        send_cmd(sock, 5, cmd);

        const char *exp[] = {"x","0.5","a","1","b","1","y","2"};
        expect_ok_multibulk(sock, exp, 8);
    }

    // Idle timeout: a connection that does nothing should be closed after ~200ms.
    {
        int sock_idle = connect_retry(port);
        assert(sock_idle >= 0);

        // Don't send anything. Wait a bit longer than server idle_ms.
        sleep_ms(350);

        expect_closed_soon(sock_idle);
        close(sock_idle);
    }

    close(sock);

    expect_server_exits_on_sigint(pid);

    puts("server_blackbox_test: OK");
    return 0;
}
