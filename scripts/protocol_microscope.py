#!/usr/bin/env python3
from __future__ import annotations

import argparse
import binascii
import socket
import struct
from typing import List, Tuple

U32BE = struct.Struct(">I")


def u32be(x: int) -> bytes:
    return U32BE.pack(x & 0xFFFFFFFF)


def hexdump(b: bytes, width: int = 16) -> str:
    # compact hex (grouped)
    hx = binascii.hexlify(b).decode()
    return " ".join(hx[i:i+2] for i in range(0, len(hx), 2))


def encode_req(argv: List[bytes]) -> bytes:
    payload = bytearray()
    payload += u32be(len(argv))
    for a in argv:
        payload += u32be(len(a))
        payload += a
    return u32be(len(payload)) + payload


def decode_req_payload(payload: bytes) -> List[bytes]:
    """  
    Client side helper to decode request payload.
    """
    if len(payload) < 4:
        raise ValueError("payload too short for argc")
    (argc,) = U32BE.unpack_from(payload, 0)
    cur = 4
    out = []
    for _ in range(argc):
        if cur + 4 > len(payload):
            raise ValueError("truncated arg len")
        (n,) = U32BE.unpack_from(payload, cur)
        cur += 4
        if cur + n > len(payload):
            raise ValueError("truncated arg bytes")
        out.append(payload[cur:cur+n])
        cur += n
    if cur != len(payload):
        raise ValueError(f"trailing bytes: {len(payload)-cur}")
    return out


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """  
    Blocking read loop to get exactly n bytes or raise EOF exception.
    """
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


def decode_res_payload(payload: bytes) -> Tuple[int, bytes]:
    if len(payload) < 8:
        raise ValueError("response payload too short")
    status = U32BE.unpack_from(payload, 0)[0]
    dlen = U32BE.unpack_from(payload, 4)[0]
    if 8 + dlen != len(payload):
        raise ValueError("bad response length")
    return status, payload[8:]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1234)
    ap.add_argument("args", nargs="+", help="command + args, e.g. set mykey hello")
    args = ap.parse_args()

    argv = [a.encode() for a in args.args]
    frame = encode_req(argv)

    print("=== Request frame (bytes on the wire) ===")
    print(hexdump(frame))
    payload = frame[4:]
    (plen,) = U32BE.unpack_from(frame, 0)
    print(f"\nouter payload_len_be = {plen} bytes")
    decoded = decode_req_payload(payload)
    print(f"argc = {len(decoded)}")
    for i, a in enumerate(decoded):
        print(f"  arg[{i}] len={len(a)} bytes={a!r}")

    with socket.create_connection((args.host, args.port)) as s:
        s.sendall(frame)
        res_frame = recv_frame(s)

    print("\n=== Response frame (bytes on the wire) ===")
    print(hexdump(res_frame))
    res_payload = res_frame[4:]
    (rplen,) = U32BE.unpack_from(res_frame, 0)
    print(f"\nouter payload_len_be = {rplen} bytes")
    status, data = decode_res_payload(res_payload)
    print(f"status = {status}")
    print(f"data_len = {len(data)}")
    print(f"data = {data!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
