#!/usr/bin/env python3
"""
Backpressure demo: create a client that DOES NOT read responses.

Steps:
1) Warm up / populate a big zset (reading responses normally).
2) Open a "slow reader" connection and spam ZRANGE responses (large payload).
3) Eventually the server should hit its MAX_OUTBUF policy and close the connection.
"""

from __future__ import annotations

import argparse
import socket
import struct
import time

U32BE = struct.Struct(">I")


def u32be(x: int) -> bytes:
    return U32BE.pack(x & 0xFFFFFFFF)


def encode_request(argv: list[bytes]) -> bytes:
    payload = bytearray()
    payload += u32be(len(argv))
    for a in argv:
        payload += u32be(len(a))
        payload += a
    return u32be(len(payload)) + payload


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("EOF")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes:
    hdr = recv_exact(sock, 4)
    (plen,) = U32BE.unpack(hdr)
    payload = recv_exact(sock, plen)
    return hdr + payload


def roundtrip(sock: socket.socket, argv: list[bytes]) -> bytes:
    sock.sendall(encode_request(argv))
    return recv_frame(sock)


def populate_zset(host: str, port: int, key: bytes, n: int) -> None:
    """  
    Opens up a normal connection to client, loops over ZADD commands and reads each response.
    This is simply to populate a ZSET for our slow reader to ZRANGE over.
    """
    with socket.create_connection((host, port)) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # Create/update N members. Read responses so this connection stays healthy.
        for i in range(n):
            member = f"user{i}".encode()
            score = str(i).encode()
            roundtrip(s, [b"zadd", key, score, member])

        # Quick check: zcard
        resp = roundtrip(s, [b"zcard", key])
        # resp is framed bytes; we don't need to parse it here.
        print(f"Populated zset with {n} members (sent zadd x{n}, zcard).")


def slow_reader_backpressure(host: str, port: int, key: bytes, start: bytes, end: bytes, withscores: bool) -> None:
    s = socket.create_connection((host, port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    # Make the client's receive buffer small so it stops ACKing window quickly.
    # (This helps trigger backpressure faster.)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    except OSError:
        pass

    argv = [b"zrange", key, start, end]
    if withscores:
        argv.append(b"withscores")
    frame = encode_request(argv)

    print("Opened slow-reader connection (will NOT recv responses).")
    print("Spamming ZRANGE frames until the server closes us...")

    sent = 0
    t0 = time.time()
    try:
        while True:
            # Send requests as fast as possible; never read responses.
            s.sendall(frame)
            sent += 1

            # Optional tiny yield to avoid totally pegging CPU (keeps demo stable).
            if sent % 200 == 0:
                time.sleep(0.001)

    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, OSError) as e:
        dt = time.time() - t0
        print(f"Send failed after {sent} requests ({dt:.2f}s): {type(e).__name__}: {e}")
        print("This is expected: server likely closed connection after output buffer hit MAX_OUTBUF.")
    finally:
        try:
            s.close()
        except Exception:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1234)
    ap.add_argument("--key", default="leaderboard")
    ap.add_argument("--members", type=int, default=1000, help="zset size to populate")
    ap.add_argument("--start", default="0")
    ap.add_argument("--end", default="-1")
    ap.add_argument("--withscores", action="store_true", default=True)
    args = ap.parse_args()

    key = args.key.encode()
    populate_zset(args.host, args.port, key, args.members)
    slow_reader_backpressure(
        args.host,
        args.port,
        key,
        args.start.encode(),
        args.end.encode(),
        args.withscores,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
