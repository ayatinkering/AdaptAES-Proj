"""Deterministic per-flow aggregation with a hard simulated queueing deadline."""

import heapq
from dataclasses import dataclass

from authenticated_records import MAX_BODY

MODES = ("immediate", "fixed", "adaptive")


@dataclass(frozen=True, slots=True)
class Packet:
    timestamp_ns: int
    flow: int
    payload: bytes
    packet_id: int


@dataclass(frozen=True, slots=True)
class Batch:
    packets: tuple[Packet, ...]
    released_ns: int
    reason: str

    @property
    def flow(self):
        return self.packets[0].flow


@dataclass(slots=True)
class Pending:
    packets: list[Packet]
    body_bytes: int
    deadline: int


def aggregate(packets, mode, max_delay_ns=1_000_000, max_packets=8, max_bytes=16384, small_bytes=512):
    if mode not in MODES or min(max_delay_ns, max_packets, max_bytes, small_bytes) < 1:
        raise ValueError("Unknown mode or nonpositive aggregation bound.")
    if max_bytes > MAX_BODY:
        raise ValueError("Batch byte limit exceeds the record format.")
    pending, previous, deadlines, batches = {}, {}, [], []

    def flush(flow, when, reason):
        state = pending.pop(flow)
        batches.append(Batch(tuple(state.packets), when, reason))

    def expire(until):
        while deadlines and deadlines[0][0] <= until:
            deadline, _, state = heapq.heappop(deadlines)
            flow = state.packets[0].flow
            if pending.get(flow) is state:
                flush(flow, deadline, "deadline")

    last_time, serial = -1, 0
    for packet in packets:
        now, flow = packet.timestamp_ns, packet.flow
        if now < last_time or not packet.payload or len(packet.payload) + 4 > MAX_BODY:
            raise ValueError("Packets must be ordered, nonempty, and fit the record format.")
        last_time = now
        if mode == "immediate":
            batches.append(Batch((packet,), now, "immediate"))
            continue
        expire(now)
        target = max_packets
        if mode == "adaptive":
            gap = now - previous.get(flow, now)
            previous[flow] = now
            # Sparse arrivals bypass buffering; bursts can amortize record overhead.
            target = min(max_packets, 1 + max_delay_ns // max(gap, 1))
            if len(packet.payload) > small_bytes:
                target = 1
        state = pending.get(flow)
        if state and (target == 1 or state.body_bytes + len(packet.payload) + 4 > max_bytes):
            flush(flow, now, "bypass" if target == 1 else "bytes")
        if target == 1:
            batches.append(Batch((packet,), now, "bypass"))
            continue
        if flow not in pending:
            pending[flow] = Pending([], 0, now + max_delay_ns)
            heapq.heappush(deadlines, (now + max_delay_ns, serial, pending[flow]))
            serial += 1
        state = pending[flow]
        state.packets.append(packet)
        state.body_bytes += len(packet.payload) + 4
        if len(state.packets) >= target or state.body_bytes >= max_bytes:
            flush(flow, now, "count" if len(state.packets) >= target else "bytes")
    # An offline trace ending does not grant an unrealistically early flush.
    expire(float("inf"))
    return batches
