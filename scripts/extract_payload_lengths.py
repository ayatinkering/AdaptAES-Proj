#!/usr/bin/env python3
"""Extract original TCP/UDP payload lengths from a PCAP file.

This works for anonymized/truncated captures when L2/L3/L4 headers are still
present. It does not require Scapy or tshark.
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
from collections import Counter
from pathlib import Path


ETH_IPV4 = 0x0800
ETH_VLAN = {0x8100, 0x88A8, 0x9100}


def u16be(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def ipv4_addr(data: bytes, offset: int) -> str:
    return ".".join(str(b) for b in data[offset : offset + 4])


def choose_rounds(payload_len: int) -> int:
    if payload_len <= 128:
        return 4
    if payload_len <= 512:
        return 6
    if payload_len <= 1024:
        return 8
    return 10


def pcap_endian(global_header: bytes) -> str:
    magic = global_header[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        return "<"
    if magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        return ">"
    raise ValueError(f"Unknown PCAP magic bytes: {magic!r}")


def ethernet_payload_offset(packet: bytes) -> tuple[int, int] | None:
    if len(packet) < 14:
        return None
    eth_type = u16be(packet, 12)
    offset = 14
    while eth_type in ETH_VLAN:
        if len(packet) < offset + 4:
            return None
        eth_type = u16be(packet, offset + 2)
        offset += 4
    return eth_type, offset


def parse_ipv4_payload(packet: bytes) -> dict[str, object] | None:
    eth = ethernet_payload_offset(packet)
    if eth is None:
        return None
    eth_type, ip_offset = eth
    if eth_type != ETH_IPV4 or len(packet) < ip_offset + 20:
        return None

    version = packet[ip_offset] >> 4
    ihl = (packet[ip_offset] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(packet) < ip_offset + ihl:
        return None

    ip_total_len = u16be(packet, ip_offset + 2)
    proto = packet[ip_offset + 9]
    src_ip = ipv4_addr(packet, ip_offset + 12)
    dst_ip = ipv4_addr(packet, ip_offset + 16)
    l4_offset = ip_offset + ihl

    if proto == 6:
        if len(packet) < l4_offset + 20:
            return None
        src_port = u16be(packet, l4_offset)
        dst_port = u16be(packet, l4_offset + 2)
        tcp_header_len = ((packet[l4_offset + 12] >> 4) & 0x0F) * 4
        if tcp_header_len < 20:
            return None
        payload_len = max(0, ip_total_len - ihl - tcp_header_len)
        return {
            "protocol": "TCP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "ip_total_length": ip_total_len,
            "payload_length": payload_len,
        }

    if proto == 17:
        if len(packet) < l4_offset + 8:
            return None
        src_port = u16be(packet, l4_offset)
        dst_port = u16be(packet, l4_offset + 2)
        udp_len = u16be(packet, l4_offset + 4)
        payload_len = max(0, udp_len - 8)
        return {
            "protocol": "UDP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "ip_total_length": ip_total_len,
            "payload_length": payload_len,
        }

    return None


def extract(pcap_path: Path, csv_path: Path, summary_path: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    total_packets = 0
    parsed_packets = 0
    payload_packets = 0
    truncated_packets = 0
    payload_bins: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    round_counts: Counter[int] = Counter()
    payload_sum = 0
    payload_min: int | None = None
    payload_max = 0

    with pcap_path.open("rb") as pcap, csv_path.open("w", newline="") as out:
        global_header = pcap.read(24)
        endian = pcap_endian(global_header)
        writer = csv.DictWriter(
            out,
            fieldnames=[
                "packet_index",
                "timestamp_seconds",
                "captured_length",
                "original_frame_length",
                "protocol",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "ip_total_length",
                "payload_length",
                "adaptaes_rounds",
            ],
        )
        writer.writeheader()

        while True:
            record_header = pcap.read(16)
            if len(record_header) < 16:
                break
            ts_sec, ts_usec, captured_len, original_len = struct.unpack(
                endian + "IIII", record_header
            )
            packet = pcap.read(captured_len)
            total_packets += 1
            if captured_len < original_len:
                truncated_packets += 1

            parsed = parse_ipv4_payload(packet)
            if parsed is None:
                continue
            parsed_packets += 1
            payload_len = int(parsed["payload_length"])
            protocol = str(parsed["protocol"])
            protocol_counts[protocol] += 1

            if payload_len <= 0:
                continue

            payload_packets += 1
            payload_sum += payload_len
            payload_min = payload_len if payload_min is None else min(payload_min, payload_len)
            payload_max = max(payload_max, payload_len)

            if payload_len <= 128:
                payload_bins["1-128"] += 1
            elif payload_len <= 512:
                payload_bins["129-512"] += 1
            elif payload_len <= 1024:
                payload_bins["513-1024"] += 1
            else:
                payload_bins[">1024"] += 1

            rounds = choose_rounds(payload_len)
            round_counts[rounds] += 1

            writer.writerow(
                {
                    "packet_index": total_packets,
                    "timestamp_seconds": f"{ts_sec}.{ts_usec:06d}",
                    "captured_length": captured_len,
                    "original_frame_length": original_len,
                    "protocol": protocol,
                    "src_ip": parsed["src_ip"],
                    "dst_ip": parsed["dst_ip"],
                    "src_port": parsed["src_port"],
                    "dst_port": parsed["dst_port"],
                    "ip_total_length": parsed["ip_total_length"],
                    "payload_length": payload_len,
                    "adaptaes_rounds": rounds,
                }
            )

    summary = {
        "pcap": str(pcap_path),
        "total_packets": total_packets,
        "parsed_tcp_udp_ipv4_packets": parsed_packets,
        "packets_with_payload": payload_packets,
        "truncated_packets": truncated_packets,
        "payload_min": payload_min or 0,
        "payload_average": (payload_sum / payload_packets) if payload_packets else 0,
        "payload_max": payload_max,
        "payload_bins": dict(payload_bins),
        "protocol_counts": dict(protocol_counts),
        "adaptaes_round_counts": {str(k): v for k, v in sorted(round_counts.items())},
    }
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--out-csv", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    extract(args.pcap, args.out_csv, args.summary)


if __name__ == "__main__":
    main()
