// server.c
//
// Single-threaded, non-blocking TCP server driven by an epoll event loop.
// Each connection maintains an input buffer (for framed requests) and an output
// buffer (for queued responses). The server supports request pipelining:
//
//   EPOLLIN  -> read() into inbuf -> decode 0+ complete frames -> execute -> queue replies
//   EPOLLOUT -> write() from outbuf until EAGAIN or drained
//
// Key invariants:
// - No blocking I/O: all sockets are O_NONBLOCK.
// - Conn buffers are byte queues:
//     in:  [0 .. in_used) are valid bytes.
//     out: [0 .. out_used) are valid bytes, with out_sent <= out_used.
// - outbuf may be compacted (memmove) to keep pending bytes contiguous.
// - If any DoS/limit guard is exceeded (MAX_*), we drop the connection.

#define _GNU_SOURCE

#include "protocol.h"
#include "db.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

enum { DEFAULT_PORT = 1234 };
enum { MAX_EVENTS = 64 };
enum { MAX_PAYLOAD = 1u << 20 };   // 1 MiB max payload (DoS guard)
enum { MAX_ARGS = 1024 };
enum { MAX_CONNS  = 1024 };
enum { MAX_INBUF  = 4u << 20 };   // 4 MiB
enum { MAX_OUTBUF = 4u << 20 };   // 4 MiB
enum { EPOLL_TICK_MS = 250 };     // epoll_wait timeout
enum { DEFAULT_IDLE_MS = 30000 }; // 30s default

// Per-connection state.
//
// Buffer invariants:
// - 0 <= in_used  <= in_cap
// - 0 <= out_sent <= out_used <= out_cap
// - pending(out) = out_used - out_sent
//
// Lifetime / ownership:
// - Conn owns in/out heap buffers and the socket fd.
// - Conn is linked into a doubly-linked list for idle sweeps.
// - If closing=true, we stop accepting new output and the connection will be dropped.
typedef struct Conn {
    int fd;

    uint8_t *in;            // inbuf
    size_t   in_cap;        // Capacity, how many bytes are allocated
    size_t   in_used;       // used length. [0..in_used) are valid buffered input data

    uint8_t *out;           // outbuf
    size_t   out_cap;       // Capacity, how many bytes are allocated
    size_t   out_used;      // used length
    size_t   out_sent;      // how many bytes have been written to socket

    bool closing;

    uint64_t last_active_ms;
    struct Conn *prev;
    struct Conn *next;
} Conn;

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static volatile sig_atomic_t g_stop = 0;

static void on_sigint(int signo) {
    (void)signo;
    g_stop = 1;
}

// Put an fd into non-blocking mode.
//
// Why:
// - We use an epoll event loop. All sockets must be non-blocking so that
//   read()/write()/accept() never stall the entire server thread.
//
// Returns 0 on success, -1 on failure.
static int set_nonblocking(int fd) {
    // F_GETFL fetches the current file status flags.
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;

    // We OR in O_NONBLOCK and write flags back with F_SETFL
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return -1;
    return 0;
}

// Parse a PSpan as a double, requiring the *entire* span to be consumed.
// PSpan is not NUL-terminated, so we copy into a bounded local buffer.
static bool span_to_double(PSpan s, double *out) {
    if (s.len == 0 || s.len > 64) return false;

    // Copy to a temporary NUL-terminated buffer for strtod().
    char tmp[65];
    memcpy(tmp, s.ptr, s.len);
    tmp[s.len] = '\0';

    char *end = NULL;
    errno = 0;
    double v = strtod(tmp, &end);

    // errno covers range errors etc. (e.g. overflow).
    if (errno != 0) return false;

    // Require that strtod consumed the entire string.
    if (end != tmp + s.len) return false;

    *out = v;
    return true;
}


// Parse a PSpan as a signed 64-bit integer (base 10), requiring full consumption.
// Same strategy as span_to_double():
static bool span_to_i64(PSpan s, int64_t *out) {
    if (s.len == 0 || s.len > 64) return false;
    char tmp[65];
    memcpy(tmp, s.ptr, s.len);
    tmp[s.len] = '\0';

    char *end = NULL;
    errno = 0;
    long long v = strtoll(tmp, &end, 10);
    if (errno != 0) return false;

    if (end != tmp + s.len) return false;

    *out = (int64_t)v;
    return true;
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    // Convert seconds + nanoseconds to milliseconds.
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

// Ensure a byte buffer has capacity >= need.
// Grows a buffers size geometrically
static bool buf_ensure(uint8_t **buf, size_t *cap, size_t need) {
    if (*cap >= need) return true;

    size_t new_cap = (*cap == 0) ? 4096 : *cap;
    while (new_cap < need) new_cap *= 2;

    uint8_t *p = (uint8_t *)realloc(*buf, new_cap);
    if (!p) return false;
    
    *buf = p;
    *cap = new_cap;
    return true;
}

// Allocate and initialize a connection state object for a newly accepted client fd.
// Note: calloc() zeroes all fields, which is convenient for invariants like:
// - in/out pointers start NULL
// - caps/used/sent start 0
// - closing flag starts false
static Conn *conn_new(int fd) {
    Conn *c = (Conn *)calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = fd;
    return c;
}

// Free all resources associated with a connection.
// This is the single exit point for tearing down a Conn
static void conn_free(Conn *c) {
    if (!c) return;
    close(c->fd);
    free(c->in);
    free(c->out);
    free(c);
}

// Append bytes to the connection's output queue.
//
// Invariant: pending bytes must remain contiguous in [0..out_used) so that
// write() can drain from (out + out_sent). If out_sent > 0, we compact first.
//
// Failure policy:
// - If appending would exceed MAX_OUTBUF, return false (caller will mark closing).
// - If realloc fails, return false.
static bool conn_out_append(Conn *c, const uint8_t *data, size_t len) {
    size_t pending = c->out_used - c->out_sent;
    if (pending + len > MAX_OUTBUF) return false;

    // Compact to reclaim front space (keeps pending bytes contiguous).
    if (c->out_sent > 0) {
        memmove(c->out, c->out + c->out_sent, pending);
        c->out_used = pending;
        c->out_sent = 0;
    }

    if (!buf_ensure(&c->out, &c->out_cap, c->out_used + len)) return false;
    memcpy(c->out + c->out_used, data, len);
    c->out_used += len;
    return true;
}

// Queue a fully-encoded response frame onto the connection.
//
// If we hit memory limits or OOM, we mark the connection for closure.
// This keeps backpressure behaviour simple: slow clients don't grow unbounded buffers.
static bool conn_queue_msg(Conn *c, const ProtoMsg *m) {
    if (!conn_out_append(c, m->buf, m->len)) {
        c->closing = true;   // hit MAX_OUTBUF or OOM => drop conn
        return false;
    }
    return true;
}

// Decide whether this connection should be subscribed to EPOLLOUT.
// Important: subscribing to EPOLLOUT when there's nothing to send can cause busy looping.
static bool conn_want_write(const Conn *c) {
    return c->out_sent < c->out_used;
}

// Update an existing epoll registration for a client fd.
// Always listen for EPOLLIN; conditionally listen for EPOLLOUT if there is
// pending output.
static void epoll_mod(int epfd, int fd, Conn *c, bool want_write) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.ptr = c;
    ev.events = EPOLLIN | (want_write ? EPOLLOUT : 0);

    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) < 0) die("epoll_ctl MOD");
}

// Register a brand-new client fd with epoll.
// We start with EPOLLIN only; EPOLLOUT is enabled later when outbuf is non-empty.
static void epoll_add(int epfd, int fd, Conn *c) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.ptr = c;
    ev.events = EPOLLIN;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) die("epoll_ctl ADD");
}

// Insert connection at the head of the global linked list.
static void conns_add(Conn **head, Conn *c) {
    c->prev = NULL;
    c->next = *head;
    if (*head) (*head)->prev = c;
    *head = c;
}

// Remove a connection from the global linked list.
static void conns_del(Conn **head, Conn *c) {
    if (c->prev) c->prev->next = c->next;
    else *head = c->next;

    if (c->next) c->next->prev = c->prev;

    c->prev = NULL;
    c->next = NULL;
}

// Send a response message:
// - queue into outbuf (may set c->closing on failure)
// - free the ProtoMsg buffer afterwards
static void reply_msg(Conn *c, ProtoMsg *msg) {
    (void)conn_queue_msg(c, msg);
    proto_msg_free(msg);
}

static void reply_err(Conn *c, const char *s) {
    ProtoMsg msg;
    if (!proto_res_encode_str(&msg, RES_ERR, s)) return;
    reply_msg(c, &msg);
}

static void reply_ok_str(Conn *c, const char *s) {
    ProtoMsg msg;
    if (!proto_res_encode_str(&msg, RES_OK, s)) return;
    reply_msg(c, &msg);
}

static void reply_ok_bytes(Conn *c, const void *p, uint32_t n) {
    ProtoMsg msg;
    if (!proto_res_encode(&msg, RES_OK, p, n)) return;
    reply_msg(c, &msg);
}

static void reply_ok_multibulk(Conn *c, uint32_t count,
                               const uint8_t *const items[], const uint32_t lens[]) {
    ProtoMsg msg;
    if (!proto_res_encode_multibulk(&msg, RES_OK, count, items, lens)) return;
    reply_msg(c, &msg);
}

static void reply_nx(Conn *c) {
    ProtoMsg msg;
    if (!proto_res_encode(&msg, RES_NX, NULL, 0)) return;
    reply_msg(c, &msg);
}

// Signature for command handlers.
// Command handlers queue their own responses onto outbuf.
typedef bool (*cmd_fn)(Conn *c, Db *db, const ProtoReq *r);

typedef struct {
    const char *name;
    uint32_t min_arity;
    uint32_t max_arity;
    cmd_fn fn;
} Cmd;

static bool cmd_ping(Conn *c, Db *db, const ProtoReq *r) {
    (void)db; (void)r;
    reply_ok_str(c, "pong");
    return true;
}

static bool cmd_set(Conn *c, Db *db, const ProtoReq *r) {
    const uint8_t *key = (const uint8_t *)r->argv[1].ptr;
    uint32_t keylen = r->argv[1].len;
    const uint8_t *val = (const uint8_t *)r->argv[2].ptr;
    uint32_t vallen = r->argv[2].len;

    if (!db_set_str(db, key, keylen, val, vallen)) {
        reply_err(c, "oom");
        return false;
    }
    reply_ok_str(c, "OK");
    return true;
}

static bool cmd_get(Conn *c, Db *db, const ProtoReq *r) {
    const uint8_t *key = (const uint8_t *)r->argv[1].ptr;
    uint32_t keylen = r->argv[1].len;

    DbEntry *e = db_get(db, key, keylen);
    if (!e) {
        reply_nx(c);
        return true;
    }
    if (e->v.type != DB_V_STR) {
        reply_err(c, "wrong type");
        return true;
    }
    reply_ok_bytes(c, e->v.as.str.data, e->v.as.str.len);
    return true;
}

static bool cmd_del(Conn *c, Db *db, const ProtoReq *r) {
    const uint8_t *key = (const uint8_t *)r->argv[1].ptr;
    uint32_t keylen = r->argv[1].len;

    bool deleted = db_del(db, key, keylen);
    reply_ok_str(c, deleted ? "1" : "0");
    return true;
}

static bool cmd_zadd(Conn *c, Db *db, const ProtoReq *r) {
    // zadd key score member
    const uint8_t *key = (const uint8_t *)r->argv[1].ptr;
    uint32_t keylen = r->argv[1].len;

    double score = 0.0;
    if (!span_to_double(r->argv[2], &score)) {
        reply_err(c, "bad request");
        return true;
    }

    const char *member = (const char *)r->argv[3].ptr;
    size_t member_len = (size_t)r->argv[3].len;

    ZSet *zs = NULL;
    DbZRes zres = db_get_or_create_zset(db, key, keylen, &zs);
    if (zres == DBZ_TYPE) {
        reply_err(c, "wrong type");
        return true;
    }
    if (zres == DBZ_OOM) {
        reply_err(c, "oom");
        return false;
    }

    bool existed = (zset_lookup(zs, member, member_len) != NULL);
    if (!zset_insert(zs, member, member_len, score)) {
        reply_err(c, "oom");
        return false;
    }

    // Redis-like: 1 if new member, 0 if updated
    reply_ok_str(c, existed ? "0" : "1");
    return true;
}

static bool cmd_zscore(Conn *c, Db *db, const ProtoReq *r) {
    // zscore key member
    const uint8_t *key = (const uint8_t *)r->argv[1].ptr;
    uint32_t keylen = r->argv[1].len;

    DbEntry *e = db_get(db, key, keylen);
    if (!e) {
        reply_nx(c);
        return true;
    }
    if (e->v.type != DB_V_ZSET) {
        reply_err(c, "wrong type");
        return true;
    }

    const char *member = (const char *)r->argv[2].ptr;
    size_t member_len = (size_t)r->argv[2].len;

    ZNode *zn = zset_lookup(e->v.as.zs, member, member_len);
    if (!zn) {
        reply_nx(c);
        return true;
    }

    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%.17g", zn->score);
    if (n < 0) {
        reply_err(c, "internal");
        return true;
    }
    reply_ok_bytes(c, buf, (uint32_t)n);
    return true;
}

static bool cmd_zrem(Conn *c, Db *db, const ProtoReq *r) {
    // zrem key member
    const uint8_t *key = (const uint8_t *)r->argv[1].ptr;
    uint32_t keylen = r->argv[1].len;

    DbEntry *e = db_get(db, key, keylen);
    if (!e) {
        reply_ok_str(c, "0");
        return true;
    }
    if (e->v.type != DB_V_ZSET) {
        reply_err(c, "wrong type");
        return true;
    }

    const char *member = (const char *)r->argv[2].ptr;
    size_t member_len = (size_t)r->argv[2].len;

    ZSet *zs = e->v.as.zs;
    ZNode *zn = zset_lookup(zs, member, member_len);
    if (!zn) {
        reply_ok_str(c, "0");
        return true;
    }

    zset_delete(zs, zn);
    reply_ok_str(c, "1");
    return true;
}

static bool cmd_zcard(Conn *c, Db *db, const ProtoReq *r) {
    // zcard key
    const uint8_t *key = (const uint8_t *)r->argv[1].ptr;
    uint32_t keylen = r->argv[1].len;

    DbEntry *e = db_get(db, key, keylen);
    if (!e) {
        reply_ok_str(c, "0");
        return true;
    }
    if (e->v.type != DB_V_ZSET) {
        reply_err(c, "wrong type");
        return true;
    }

    // AVL stores subtree counts, so root->count is cardinality.
    size_t n = avl_count(e->v.as.zs->root);
    char buf[32];
    int w = snprintf(buf, sizeof(buf), "%zu", n);
    if (w < 0) {
        reply_err(c, "internal");
        return true;
    }
    reply_ok_bytes(c, buf, (uint32_t)w);
    return true;
}

static bool cmd_zrange(Conn *c, Db *db, const ProtoReq *r) {
    // zrange key start end withscores
    const uint8_t *key = (const uint8_t *)r->argv[1].ptr;
    uint32_t keylen = r->argv[1].len;

    int64_t start = 0, end = 0;
    if (!span_to_i64(r->argv[2], &start) || !span_to_i64(r->argv[3], &end)) {
        reply_err(c, "bad request");
        return true;
    }

    bool withscores = false;
    if (r->argc == 5) {
        // strict: require exactly "withscores"
        if (r->argv[4].len == 10 && memcmp(r->argv[4].ptr, "withscores", 10) == 0) {
            withscores = true;
        } else {
            reply_err(c, "expected 'withscores' for 5th argument");
            return true;
        }
    }

    DbEntry *e = db_get(db, key, keylen);
    if (!e) {
        // Redis-like: missing key => empty list
        reply_ok_multibulk(c, 0, NULL, NULL);
        return true;
    }
    if (e->v.type != DB_V_ZSET) {
        reply_err(c, "wrong type");
        return true;
    }

    size_t cnt = 0;
    ZNode **nodes = zset_range(e->v.as.zs, start, end, &cnt);
    if (!nodes) {
        if (cnt == 0) {
            reply_ok_multibulk(c, 0, NULL, NULL);
            return true;
        }
        reply_err(c, "oom");
        return false;
    }

    uint32_t out_cnt = withscores ? 2u * (uint32_t)cnt : (uint32_t)cnt;
    const uint8_t **items = (const uint8_t **)malloc(out_cnt * sizeof(*items));
    uint32_t *lens = (uint32_t *)malloc(out_cnt * sizeof(*lens));

    // For scores we need stable storage until proto_res_encode_multibulk copies it.
    char *score_buf = NULL;
    if (!items || !lens) goto oom;

    if (withscores) {
        score_buf = malloc(cnt * 64);
        if (!score_buf) goto oom;
        for (size_t i = 0; i < cnt; i++) {
            items[2*i] = (const uint8_t*)nodes[i]->key;
            lens [2*i] = (uint32_t)nodes[i]->keylen;

            char *dst = score_buf + i*64;
            int n = snprintf(dst, 64, "%.17g", nodes[i]->score);
            if (n < 0 || n >= 64) goto internal;

            items[2*i+1] = (const uint8_t*)dst;
            lens [2*i+1] = (uint32_t)n;
        }
    } else {
        for (size_t i = 0; i < cnt; i++) {
            items[i] = (const uint8_t*)nodes[i]->key;
            lens [i] = (uint32_t)nodes[i]->keylen;
        }
    }

    reply_ok_multibulk(c, out_cnt, items, lens);
    goto done;

    oom:
    reply_err(c, "oom");
    goto done;

    internal:
    reply_err(c, "internal");
    goto done;

    done:
    free(score_buf);
    free(items);
    free(lens);
    free(nodes);
    return true;
}

// Command table + dispatch
// - name: command literal (lowercase ASCII)
// - min_arity/max_arity: argument count validation (including the command itself)
// - fn: handler implementation
static const Cmd g_cmds[] = {
    { "ping",   1, 1, cmd_ping   },
    { "set",    3, 3, cmd_set    },
    { "get",    2, 2, cmd_get    },
    { "del",    2, 2, cmd_del    },
    { "zadd",   4, 4, cmd_zadd   },
    { "zscore", 3, 3, cmd_zscore },
    { "zrem",   3, 3, cmd_zrem   },
    { "zcard",  2, 2, cmd_zcard  },
    { "zrange", 4, 5, cmd_zrange },
};

// Find a command definition by name.
// - Input is a PSpan (pointer + length), i.e. not necessarily NUL-terminated.
// - We do an exact match on length + bytes (memcmp).
// - Returns NULL if unknown.
//
// This is called on every request, but g_cmds is small (O(#cmds) is fine).
static const Cmd *find_cmd(PSpan name) {
    for (size_t i = 0; i < sizeof(g_cmds)/sizeof(g_cmds[0]); i++) {
        const Cmd *c = &g_cmds[i];
        // c->name is a C string; compute its length once per entry.
        size_t n = strlen(c->name);
        // Exact match: same length and same bytes.
        if (name.len == n && memcmp(name.ptr, c->name, n) == 0) {
            return c;
        }
    }
    return NULL;
}

// Top-level request handler for *one* decoded request.
// This function does not touch raw socket bytes; it operates on decoded argv[].
//
// Behaviour:
// - argc==0 is invalid.
// - unknown command -> ERR "not implemented".
// - arity mismatch -> ERR "bad arity".
// - otherwise call the handler.
//
// The handler is responsible for producing a response (queueing into outbuf).
static void handle_request(Conn *c, Db *db, const ProtoReq *r) {
    if (r->argc == 0) {
        reply_err(c, "bad request");
        return;
    }
    
    // Lookup command by argv[0].
    const Cmd *cmd = find_cmd(r->argv[0]);
    if (!cmd) {
        reply_err(c, "not implemented");
        return;
    }

    if (r->argc < cmd->min_arity || r->argc > cmd->max_arity) {
        reply_err(c, "bad arity");
        return;
    }

    (void)cmd->fn(c, db, r);
}

// Decode and handle as many complete request frames as are currently buffered.
//
// Behaviour:
// - Supports pipelining: multiple frames can be processed per EPOLLIN wakeup.
// - DoS guard: if a frame declares payload_len > MAX_PAYLOAD, drop connection.
// - On decode error: attempt to queue an ERR response, then drop connection.
// - After consuming a frame, remaining bytes are memmoved to the front.
static bool conn_process_frames(Conn *c, Db *db) {
    // Process as many complete frames as we have (pipelining).
    while (true) {
        // If we have the length header, we can detect oversize frames immediately.
        if (c->in_used >= 4) {
            uint32_t payload_len = 0;
            (void)proto_frame_peek_len(c->in, c->in_used, &payload_len);
            if (payload_len > MAX_PAYLOAD) {
                return false; // drop connection (DoS guard)
            }
        }

        // Check whether we currently have a *complete* frame buffered.
        // If not, we keep the connection alive and wait for more EPOLLIN data.
        size_t frame_bytes = 0;
        if (!proto_frame_ready(c->in, c->in_used, MAX_PAYLOAD, &frame_bytes)) {
            return true; // need more data or invalid len not yet detectable
        }

        // We have a full frame at front of inbuf: [u32 payload_len][payload...]
        uint32_t payload_len = 0;
        (void)proto_frame_peek_len(c->in, c->in_used, &payload_len);
        const uint8_t *payload = c->in + 4;

        // Decode request payload into argv[] spans.
        // IMPORTANT: argv[i].ptr points *into payload*, which points *into c->in*.
        // That means we must not memmove/overwrite c->in until after we finish
        // handling this request.
        ProtoReq req;
        bool ok = proto_req_decode(&req, payload, payload_len, MAX_ARGS);
        if (!ok) {
            ProtoMsg err;
            if (proto_res_encode_str(&err, RES_ERR, "bad request")) {
                (void)conn_queue_msg(c, &err);
                proto_msg_free(&err);
            }
            // Close immediately on protocol violations
            return false;
        }

        // Execute the command. Handler will queue a response into outbuf.
        handle_request(c, db, &req);

        // Free argv[] array
        proto_req_free(&req);

        if (c->closing) return false;

        // Consume frame_bytes from input buffer.
        size_t remain = c->in_used - frame_bytes;
        // Shift remaining bytes down so inbuf always starts at offset 0.
        if (remain > 0) memmove(c->in, c->in + frame_bytes, remain);
        c->in_used = remain;
    }
} 

// Read handler: drain the socket into inbuf until EAGAIN.
//
// Invariants / guards:
// - inbuf grows geometrically; hard capped by MAX_INBUF to prevent memory abuse.
// - last_active_ms updated on successful read/write activity.
// - After reading, we attempt to process buffered frames.
static bool conn_readable(Conn *c, Db *db) {
    for (;;) {
        // Guardrail: avoid unbounded per-connection memory growth.
        // Reserve up to 4096 bytes per iteration.
        if (c->in_used + 4096 > MAX_INBUF) return false;
        // Ensure space for at least one more read chunk.
        if (!buf_ensure(&c->in, &c->in_cap, c->in_used + 4096)) return false;

        // Read as much as the kernel will give us right now.
        ssize_t n = read(c->fd, c->in + c->in_used, c->in_cap - c->in_used);
        if (n > 0) {
            c->in_used += (size_t)n;
            c->last_active_ms = now_ms();
            continue;
        }
        if (n == 0) {
            // peer closed
            return false;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No more bytes to read right now.
            break;
        }
        if (errno == EINTR) continue;
        // Any other error: treat as fatal.
        return false;
    }
    // We’ve drained the fd for now; execute any full frames currently buffered.
    return conn_process_frames(c, db);
}

// Write handler: drain as much of outbuf as possible until EAGAIN or fully sent.
//
// Invariant:
// - out_sent only moves forward.
// - If fully drained, we reset (out_sent=0, out_used=0) to keep the queue empty-state simple.
static bool conn_writable(Conn *c) {
    while (c->out_sent < c->out_used) {
        // Try to write the remaining queued bytes.
        ssize_t n = write(c->fd, c->out + c->out_sent, c->out_used - c->out_sent);

        if (n > 0) {
            // Progress: advance sent pointer and continue draining.
            c->out_sent += (size_t)n;
            c->last_active_ms = now_ms();
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        if (n < 0 && errno == EINTR) continue;
        return false;
    }

    // compact if fully sent
    if (c->out_sent == c->out_used) {
        c->out_sent = 0;
        c->out_used = 0;
    }
    return true;
}

// Create and configure the listening socket.
// Returns a non-blocking TCP/IPv4 listening fd bound to INADDR_ANY:port.
static int make_listener(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);       // Creates a TCP/IPv4 socket.
    if (fd < 0) die("socket");

    int one = 1;
    // Allows rebinding to the same port shortly after restarting the server.
    // Without this, you often hit "Address already in use" because the previous
    // socket remains in TIME_WAIT for a while.
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) die("setsockopt");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    // Associates the socket with a local address: INADDR_ANY + port.
    // INADDR_ANY means “accept connections on all network interfaces”.
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");

    // Puts the socket into passive mode so it can accept incoming connections.
    // The backlog controls how many pending connections can queue before accept().
    if (listen(fd, 128) < 0) die("listen");

    if (set_nonblocking(fd) < 0) die("set_nonblocking(listener)");

    return fd;
}

int main(int argc, char **argv) {
    int port = DEFAULT_PORT;
    if (argc >= 2) port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "invalid port\n");
        return 2;
    }
    // --- Create listening socket ---
    int lfd = make_listener(port);

    // --- Create epoll instance ---
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) die("epoll_create1");

    // epoll data.ptr convention:
    // - listener fd uses data.ptr == NULL
    // - client fds use data.ptr == Conn*
    // Register listener with epoll (data.ptr == NULL means listener).
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = NULL;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &ev) < 0) die("epoll_ctl ADD listener");

    printf("listening on port %d\n", port);

    struct epoll_event events[MAX_EVENTS];

    // Initialise DB (DS internals are black boxes to server.c)
    Db db;
    db_init(&db);

    // --- Connection tracking ---
    size_t live_conns = 0;
    Conn *conns_head = NULL;

    // --- Idle timeout config ---
    uint64_t idle_ms = DEFAULT_IDLE_MS;
    if (argc >= 3) idle_ms = (uint64_t)strtoull(argv[2], NULL, 10);
    uint64_t last_sweep_ms = now_ms();

    // --- SIGINT handling: set g_stop, then main loop exits cleanly ---
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) < 0) die("sigaction(SIGINT)");

    // --- Main event loop ---
    while (!g_stop) {
        int n = epoll_wait(epfd, events, MAX_EVENTS, EPOLL_TICK_MS);
        if (n < 0) {
            if (errno == EINTR) continue;
            die("epoll_wait");
        }

        // Idle timeout sweep:
        // - We maintain a linked list of all live connections.
        // - Once per second, drop connections idle longer than idle_ms (if enabled).
        // - We must save next before freeing current (iterator invalidation).
        uint64_t now = now_ms();
        if (now - last_sweep_ms >= 1000 && idle_ms > 0) {
            last_sweep_ms = now;

            Conn *it = conns_head;
            while (it) {
                Conn *next = it->next; // save next before possibly freeing

                if (now - it->last_active_ms > idle_ms) {
                    epoll_ctl(epfd, EPOLL_CTL_DEL, it->fd, NULL);
                    conns_del(&conns_head, it);
                    conn_free(it);
                    live_conns--;
                }

                it = next;
            }
        }

        if (g_stop) break;

        // Handle each ready event.
        for (int i = 0; i < n; i++) {
            uint32_t e = events[i].events;

            if (events[i].data.ptr == NULL) {
                // listener ready (new client connections to accept)
                for (;;) {
                    struct sockaddr_in cli;
                    socklen_t clilen = sizeof(cli);
                    int cfd = accept(lfd, (struct sockaddr *)&cli, &clilen);
                    if (cfd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno == EINTR) continue;
                        perror("accept");
                        break;
                    }

                    // Enforce connection cap (DoS guard).
                    if (live_conns >= MAX_CONNS) {
                        close(cfd);
                        continue;
                    }

                    // Make client socket non-blocking.
                    if (set_nonblocking(cfd) < 0) {
                        close(cfd);
                        continue;
                    }

                    // Allocate per-connection state (inbuf/outbuf, counters).
                    Conn *c = conn_new(cfd);
                    if (!c) {
                        close(cfd);
                        continue;
                    }
                    c->last_active_ms = now_ms();
                    conns_add(&conns_head, c);

                    // Register client in epoll. Initially EPOLLIN only;
                    // EPOLLOUT is enabled dynamically when outbuf has pending bytes.
                    epoll_add(epfd, cfd, c);
                    live_conns++;
                }
                continue;
            }

            // Client event
            Conn *c = (Conn *)events[i].data.ptr;

            // Error/hangup means the fd is not usable; drop it.
            if (e & (EPOLLERR | EPOLLHUP)) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
                conns_del(&conns_head, c);
                conn_free(c);
                live_conns--;
                continue;
            }

            bool ok = true;

            // EPOLLIN: read bytes -> inbuf -> parse/execute frames -> queue responses.
            if (e & EPOLLIN) {
                ok = conn_readable(c, &db);
            }
            
            // EPOLLOUT: attempt to flush queued response bytes from outbuf.
            if (ok && (e & EPOLLOUT)) {
                ok = conn_writable(c);
            }

            if (!ok) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
                conns_del(&conns_head, c);
                conn_free(c);
                live_conns--;
                continue;
            }

            // Update EPOLLOUT subscription based on whether we have pending output.
            // This prevents busy looping on writable sockets when there's nothing to send.
            epoll_mod(epfd, c->fd, c, conn_want_write(c));
        }
    }
    // Stop accepting new connections.
    epoll_ctl(epfd, EPOLL_CTL_DEL, lfd, NULL);
    close(lfd);

    // Close all client connections
    Conn *it = conns_head;
    while (it) {
        Conn *next = it->next;
        epoll_ctl(epfd, EPOLL_CTL_DEL, it->fd, NULL);
        conns_del(&conns_head, it);
        conn_free(it);
        live_conns--;
        it = next;
    }

    close(epfd);
    db_destroy(&db);
    return 0;
}
