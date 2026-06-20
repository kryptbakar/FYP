"""Generate a tiny, deterministic PCAP for offline Suricata/Zeek testing.

Writes a single valid DNS-over-UDP query (example.com A IN) so Suricata/Zeek
parse a real packet and emit eve.json / logs — no live capture or network needed.
This keeps Phase B verification reproducible on an air-gapped lab box.

Usage: python make_test_pcap.py [out.pcap]
"""
from __future__ import annotations

import struct
import sys


def ipv4_checksum(header: bytes) -> int:
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) + header[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def dns_query(name: str = "example.com") -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)  # id, flags(RD), qd=1
    qname = b"".join(struct.pack("B", len(p)) + p.encode() for p in name.split(".")) + b"\x00"
    question = qname + struct.pack(">HH", 1, 1)  # type A, class IN
    return header + question


def build_packet() -> bytes:
    dns = dns_query()
    # UDP: src 40000 -> dst 53, checksum 0 (optional for IPv4)
    udp = struct.pack(">HHHH", 40000, 53, 8 + len(dns), 0) + dns
    # IPv4 header
    total_len = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s",
                     0x45, 0x00, total_len, 0x0001, 0x0000, 64, 17, 0,
                     bytes([10, 0, 0, 10]), bytes([8, 8, 8, 8]))
    ip = ip[:10] + struct.pack(">H", ipv4_checksum(ip)) + ip[12:]
    # Ethernet: dst, src, type IPv4
    eth = bytes.fromhex("aaaaaaaaaaaa") + bytes.fromhex("bbbbbbbbbbbb") + struct.pack(">H", 0x0800)
    return eth + ip + udp


def write_pcap(path: str) -> None:
    pkt = build_packet()
    with open(path, "wb") as f:
        # pcap global header: magic, v2.4, tz0, sig0, snaplen, linktype=1 (Ethernet)
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        # one record: ts_sec, ts_usec, incl_len, orig_len
        f.write(struct.pack("<IIII", 1717200000, 0, len(pkt), len(pkt)))
        f.write(pkt)
    print(f"wrote {path} ({len(pkt)} byte DNS query packet)")


if __name__ == "__main__":
    write_pcap(sys.argv[1] if len(sys.argv) > 1 else "test.pcap")
