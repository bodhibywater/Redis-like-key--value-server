#!/usr/bin/env python3
"""
Concurrent latency benchmark for the custom binary protocol server.

Writes a CSV with per-request latency (ms).
Default workload is a small fixed mix of SET/GET/ZADD/ZRANGE to exercise both string + zset paths.

Usage example:
  python3 scripts/bench_latency.py --host 127.0.0.1 --port 1234 --clients 50 --requests 200 --out bench.csv
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import os
import random
import socket
import struct
import time
from dataclasses import dataclass
from typing import Iterable, List, Tuple


U32BE = struct.Struct(">I")


def enc_u32be(x: int) -> bytes:
    """
    Packs an int into a big-endian u32.
    """
    return U32BE.pack(x & 0xFFFFFFFF)


def encode_request(args: List[bytes]) -> bytes:
    """
    Encodes request format that server expects.
    """
    # payload := [argc][len][bytes]...
    payload = bytearray()
    payload += enc_u32be(len(args))
    for a in args:
        payload += enc_u32be(len(a))
        payload += a
    frame = bytearray()
    frame += enc_u32be(len(payload))
    frame += payload
    return bytes(frame)


def decode_response(payload: bytes) -> Tuple[int, bytes]:
    """  
    Parse response payloads.
    """
    # payload := [status][dlen][data]
    if len(payload) < 8:
        raise ValueError(f"response payload too short: {len(payload)}")
    status = U32BE.unpack_from(payload, 0)[0]
    dlen = U32BE.unpack_from(payload, 4)[0]
    if 8 + dlen != len(payload):
        raise ValueError(f"bad dlen: want 8+{dlen}=={len(payload)}")
    return status, payload[8:]


async def read_exactly(reader: asyncio.StreamReader, n: int) -> bytes:
    return await reader.readexactly(n)


async def read_frame(reader: asyncio.StreamReader) -> bytes:
    hdr = await read_exactly(reader, 4)
    (plen,) = U32BE.unpack(hdr)
    payload = await read_exactly(reader, plen)
    return payload


@dataclass(frozen=True)
class WorkItem:
    name: str
    args: List[bytes]


def make_workload(seed: int, zkey: str = "leaderboard") -> List[WorkItem]:
    """
    A small deterministic request mix.
    Keeps keys short and reuses the same zset key to reduce noise.
    """
    rnd = random.Random(seed)
    zkey_b = zkey.encode()

    items: List[WorkItem] = []

    # A tiny pool of members/keys so updates hit both insert + update paths.
    members = [f"user{i}".encode() for i in range(50)]
    keys = [f"k{i}".encode() for i in range(50)]

    # Weighted mix.
    # (name, weight, generator)
    def gen_set() -> WorkItem:
        k = rnd.choice(keys)
        v = os.urandom(16)
        return WorkItem("set", [b"set", k, v])

    def gen_get() -> WorkItem:
        k = rnd.choice(keys)
        return WorkItem("get", [b"get", k])

    def gen_zadd() -> WorkItem:
        m = rnd.choice(members)
        score = rnd.randint(0, 100)
        return WorkItem("zadd", [b"zadd", zkey_b, str(score).encode(), m])

    def gen_zrange() -> WorkItem:
        # small range; includes optional withscores sometimes
        if rnd.random() < 0.5:
            return WorkItem("zrange", [b"zrange", zkey_b, b"0", b"10"])
        return WorkItem("zrange_withscores", [b"zrange", zkey_b, b"0", b"10", b"withscores"])

    weighted = [
        (40, gen_get),
        (25, gen_set),
        (20, gen_zadd),
        (15, gen_zrange),
    ]

    # Build a 1000-item repeating schedule deterministically.
    schedule: List[WorkItem] = []
    for _ in range(1000):
        r = rnd.randint(1, 100)
        acc = 0
        for w, g in weighted:
            acc += w
            if r <= acc:
                schedule.append(g())
                break

    return schedule


async def one_client(
    client_id: int,
    host: str,
    port: int,
    requests: int,
    warmup: int,
    schedule: List[WorkItem],
    start_barrier: asyncio.Event,
    results: List[Tuple[int, int, str, float, int]],
) -> None:
    # Connect to server over TCP
    reader, writer = await asyncio.open_connection(host, port)

    # Disable Nagle for cleaner latency signals.
    sock: socket.socket | None = writer.get_extra_info("socket")
    if sock is not None:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass

    # Sync start so clients hit together.
    await start_barrier.wait()

    # Warmup (not recorded): primes allocations, caches, etc.
    for i in range(warmup):
        wi = schedule[(client_id * 997 + i) % len(schedule)]
        writer.write(encode_request(wi.args))
        await writer.drain()
        _ = await read_frame(reader)

    # Measured requests
    for i in range(requests):
        wi = schedule[(client_id * 997 + warmup + i) % len(schedule)]
        frame = encode_request(wi.args)

        t0 = time.perf_counter_ns()
        writer.write(frame)
        await writer.drain()
        payload = await read_frame(reader)
        t1 = time.perf_counter_ns()

        status, _data = decode_response(payload)
        latency_ms = (t1 - t0) / 1_000_000.0
        # store: client_id, req_idx, name, latency_ms, status
        results.append((client_id, i, wi.name, latency_ms, status))

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


def percentiles(xs: List[float], ps: Iterable[float]) -> List[float]:
    if not xs:
        return [float("nan") for _ in ps]
    ys = sorted(xs)
    out = []
    for p in ps:
        k = int(round((p / 100.0) * (len(ys) - 1)))
        k = max(0, min(k, len(ys) - 1))
        out.append(ys[k])
    return out


def summarize_by_op(results: List[Tuple[int, int, str, float, int]]) -> None:
    # results rows: (client_id, req_idx, op, latency_ms, status)
    by_op: dict[str, List[float]] = {}
    for _cid, _idx, op, lat_ms, _status in results:
        by_op.setdefault(op, []).append(lat_ms)

    print("\nPer-op latency (ms):")
    print(f"{'op':20s} {'n':>7s} {'mean':>8s} {'p50':>8s} {'p95':>8s} {'p99':>8s}")
    for op in sorted(by_op.keys()):
        xs = by_op[op]
        p50, p95, p99 = percentiles(xs, [50, 95, 99])
        mean = sum(xs) / len(xs)
        print(f"{op:20s} {len(xs):7d} {mean:8.3f} {p50:8.3f} {p95:8.3f} {p99:8.3f}")


async def main_async() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1234)
    ap.add_argument("--clients", type=int, default=50)
    ap.add_argument("--requests", type=int, default=200, help="measured requests per client")
    ap.add_argument("--warmup", type=int, default=20, help="warmup requests per client (not recorded)")
    ap.add_argument("--seed", type=int, default=123)
    ap.add_argument("--out", default="bench.csv")
    args = ap.parse_args()

    schedule = make_workload(args.seed)

    # One list shared by all tasks; append is safe enough here (single-threaded event loop).
    results: List[Tuple[int, int, str, float, int]] = []

    start_barrier = asyncio.Event()

    tasks = [
        asyncio.create_task(
            one_client(
                client_id=i,
                host=args.host,
                port=args.port,
                requests=args.requests,
                warmup=args.warmup,
                schedule=schedule,
                start_barrier=start_barrier,
                results=results,
            )
        )
        for i in range(args.clients)
    ]

    # Release all clients at once.
    start_barrier.set()

    t0 = time.perf_counter()
    await asyncio.gather(*tasks)
    t1 = time.perf_counter()

    # Write CSV
    results.sort(key=lambda r: (r[0], r[1]))
    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["client_id", "req_idx", "op", "latency_ms", "status"])
        w.writerows(results)

    latencies = [r[3] for r in results]
    p50, p95, p99 = percentiles(latencies, [50, 95, 99])
    total_reqs = args.clients * args.requests
    dur = max(1e-9, (t1 - t0))
    rps = total_reqs / dur

    print(f"Wrote {args.out} ({len(results)} samples)")
    print(f"Clients: {args.clients}, Requests/client: {args.requests}, Warmup/client: {args.warmup}")
    print(f"Throughput: {rps:.1f} req/s over {dur:.3f}s")
    print(f"Latency ms: p50={p50:.3f}  p95={p95:.3f}  p99={p99:.3f}  mean={sum(latencies)/len(latencies):.3f}")
    summarize_by_op(results)
    return 0


def main() -> int:
    try:
        return asyncio.run(main_async())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
