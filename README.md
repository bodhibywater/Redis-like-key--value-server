# Epoll Key-Value Server (Redis-ish) — C17

A small, single-threaded, **in-memory** key-value server written in C, built around a non-blocking TCP listener and an **epoll** event loop.

It supports:
- **String keys** (`SET/GET/DEL`)
- **Sorted sets** (`ZADD/ZSCORE/ZREM/ZCARD/ZRANGE`) backed by an AVL tree + hash map

This is **not** Redis-compatible (custom binary protocol), but the command semantics are intentionally Redis-like.

## Build

Requirements: `Linux (epoll)`, `gcc`, `make`.
```
make
```

Binaries produced:
- `./server`
- `./client`

Object files are placed under build/ 

## Run

### Start the server

```
./server [port] [idle_timeout_ms]
```
- `port` defaults to 1234
- `idle_timeout_ms` defaults to `30000` (30s)
- set `idle_timeout_ms` to `0` to disable idle timeouts

Examples:

```
./server
./server 1234
./server 1234 0
./server 5555 60000
```

You should see:
```
listening on port <port>
```

### Use the client

The included `client` is a minimal request/response tool.

**Important:** it always connects to 127.0.0.1:1234 (hard-coded).
So run the server on port 1234, or adjust `client.c` if you want a different host/port.

Examples:
```
./client ping
./client set mykey hello
./client get mykey
./client del mykey

./client zadd leaderboard 10 alice
./client zadd leaderboard 7 bob
./client zscore leaderboard alice
./client zcard leaderboard
./client zrange leaderboard 0 -1
./client zrange leaderboard 0 -1 withscores
./client zrem leaderboard bob
```
Client output format:
```
server says: [<status>] <payload...>
```

## Commands

All command names are **lowercase.**

### Strings
- `ping`
	- reply: `pong`
- `set <key> <value>`
	- reply: `OK`
- `get <key>`
	- reply: value bytes, or NX if missing.
	- error if key exists but is not a string: `wrong type`
- `del <key>`
	- reply: `"1"` if deleted, `"0"` if not present

### Sorted sets

Sorted set commands operate on a key whose value is a ZSet.
- `zadd <key> <score> <member>`
	- reply: `"1"` if new member, `"0"` if updated
	- error if key exists but is not a zset: `wrong type`
- `zscore <key> <member>`
	- reply: score as a decimal string, or `NX` if missing
- `zrem <key> <member>`
	- reply: `"1"` if removed, `"0"` otherwise
- `zcard <key>`
	- reply: cardinality (as decimal string)
- `zrange <key> <start> <end> [withscores]`
	- `start`/`end` are **inclusive** ranks
	- supports **negative indices** (Redis-like)
	- if `[withscores]` is present it must be exactly the literal `withscores`
	- reply: a “multi-bulk” list
		- without `withscores`: `[member, member, ...]`
		- with `withscores`: `[member, score, member, score, ...]`
	- missing key returns an empty list (status OK, count = 0)

## Protocol (binary, length-prefixed)

This project uses a simple framed protocol over TCP.

All integer fields are **unsigned 32-bit big-endian** (network byte order).
All “bytes” fields are raw byte sequences (not null-terminated).

### Request frame
```
[u32 payload_len_be]
[payload_bytes...]
```
Payload layout:
```
[u32 argc_be]
repeat argc times:
  [u32 arg_len_be]
  [arg bytes...]
```

### Response frame
Same outer frame:
```
[u32 payload_len_be]
[payload_bytes...]
```
Payload layout:
```
[u32 status_be]
[u32 data_len_be]
[data bytes...]
```
Status codes:
- `0` = OK
- `1` = ERR
- `2` = NX (not found)

For `ZRANGE`, the `data` bytes are "multi-bulk" encoding:
```
[u32 count_be]
repeat count times:
  [u32 item_len_be]
  [item bytes...]
```

## Architecture (high-level)

### Server event loop
- non-blocking listener + non-blocking client sockets
- `epoll_wait` drives:
	- readable events -> `read()` into per-connection `inbuf` -> decode 0+ complete frames 
	(supports partial reads + pipelining) -> execute commands
	- writable events -> flush per-connection `outbuf`; when empty, disable EPOLLOUT interest 

### Connection state

Each connection has:
- `inbuf` (grows as needed, capped at **4 MiB**)
- `outbuf` (append-only queue with compaction, capped at **4 MiB**)
- `last_active_ms` for idle timeout sweeps
- a `closing` flag when limits/oom conditions are hit

### Data model

Top-level DB is a hash map from key -> value where value is either:
- string (heap-allocated bytes)
- sorted set pointer

Sorted set (`ZSet`) is implemented as:
- hashmap for O(1) lookup by member key (`ZSCORE`/`ZREM`)
- AVL tree ordered by `(score, key)` for `ZRANGE` / ordered insertions
- AVL subtree counts are maintained, so `zcard` is O(1) via `root->count`

## Limits / guardrails

Current server-side limits (hard-coded)
- max connections: `1024`
- max request payload: `1 MiB`
- max args: `1024`
- max per-connection input buffer: `4 MiB`
- max per-connection output buffer: `4 MiB`
- idle timeout sweep: once per second (disabled if `idle_timeout_ms == 0`)

Client-side limit:
- max request size is `4096` bytes

## Tests

Run unit tests + blackbox test:
```
make test
```
Sanitisers:
```
make asan
make asan-test
```

Notes:
- test executables are built under `bin/`
- object files are under `build/`
- `make clean` removes `build/`, `bin/` and the root `server`/`client`

## Scripts (bench / demos)

Scripts live under `scripts/`:
- `bench_latency.py` - concurrent latency benchmark (writes a CSV)
- `plot_latency.py` - plot latency histogram from a CSV (requires `matplotlib`)
- `protocol_microscope.py` - print request/response frames as hex + decoded fields
- `backpressure.py` - open a slow-reader connection and demonstrate output-buffer pressure

Examples
```
python3 scripts/bench_latency.py --clients 50 --requests 200 --warmup 20 --out bench.csv
python3 scripts/plot_latency.py bench.csv --out latency.png
python3 scripts/protocol_microscope.py --host 127.0.0.1 --port 1234 set mykey hello
python3 scripts/backpressure.py --host 127.0.0.1 --port 1234 --members 1000 --withscores

```

## Repository map
- `src/server/server.c` - TCP server + epoll event loop + command handlers
- `src/server/protocol.[ch]` - framing + request decode + response encode 
- `src/ds/db.[ch]` - key -> (string|zset) database layer (top-level ownership)
- `src/ds/hashtable.[ch]` - intrusive hash map with incremental rehashing
- `src/ds/avltree.[ch]` - intrusive AVL tree implementation
- `src/ds/zset.[ch]` - sorted set: AVL (ordered) + hash map (member lookup)
- `src/client/client.c` - minimal binary-protocol client (connects to 127.0.0.1:1234)
- `tests/*.c` - unit tests + integration-style blackbox test
- `scripts/*.py` - benchmark + protocol/backpressure demos