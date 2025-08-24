# adapters.py
import sys
from ips_core import IPSCore, Verdict
try:
    from scapy.all import rdpcap, sniff, TCP, UDP, ICMP, Raw
except Exception:
    rdpcap = None
    sniff = None
    TCP = UDP = ICMP = Raw = None

def _to_event(pkt):
    ts = float(pkt.time)
    src = pkt[0][1].src if hasattr(pkt[0][1], "src") else "0.0.0.0"
    dst = pkt[0][1].dst if hasattr(pkt[0][1], "dst") else "0.0.0.0"
    proto = None
    sport = None
    dport = None
    tcp_flags = {}

    payload = b""
    if TCP and pkt.haslayer(TCP):
        proto = "TCP"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        fl = pkt[TCP].flags
        tcp_flags = {
            "S": bool(fl & 0x02),
            "A": bool(fl & 0x10),
            "F": bool(fl & 0x01),
            "R": bool(fl & 0x04),
            "P": bool(fl & 0x08),
            "U": bool(fl & 0x20),
            "NULL": (fl == 0)
        }
        if Raw and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)

    elif UDP and pkt.haslayer(UDP):
        proto = "UDP"
        sport = int(pkt[UDP].sport)
        dport = int(pkt[UDP].dport)
        if Raw and pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)

    elif ICMP and pkt.haslayer(ICMP):
        proto = "ICMP"

    else:
        proto = "OTHER"

    return {
        "ts": ts, "src": src, "dst": dst, "proto": proto,
        "sport": sport, "dport": dport, "tcp_flags": tcp_flags, "payload": payload
    }

def run_pcap(path, ips: IPSCore, print_allowed=False):
    if rdpcap is None:
        print("Scapy not available. Install scapy to use PCAP mode.", file=sys.stderr)
        sys.exit(2)
    pkts = rdpcap(path)
    blocks = 0
    total = 0
    for pkt in pkts:
        ev = _to_event(pkt)
        verdict = ips.decide(ev)
        total += 1
        if verdict.decision == Verdict.BLOCK:
            blocks += 1
            print(f"[BLOCK] {verdict.reason} :: {ev['src']} -> {ev['dst']} {ev['proto']}:{ev.get('dport')}")
        elif print_allowed:
            print(f"[ALLOW] {ev['src']} -> {ev['dst']} {ev['proto']}:{ev.get('dport')}")
    print(f"\nSummary: total={total}, blocked={blocks}, allowed={total-blocks}")
    return blocks, total

def run_live(interface, ips: IPSCore):
    if sniff is None:
        print("Scapy not available. Install scapy to use live sniff mode.", file=sys.stderr)
        sys.exit(2)

    def _cb(pkt):
        ev = _to_event(pkt)
        v = ips.decide(ev)
        if v.decision == "BLOCK":
            print(f"[LIVE BLOCK] {v.reason} :: {ev['src']} -> {ev['dst']} {ev['proto']}:{ev.get('dport')}")

    print(f"[*] Sniffing on {interface} (CTRL+C to stop)")
    sniff(iface=interface, prn=_cb, store=False)
