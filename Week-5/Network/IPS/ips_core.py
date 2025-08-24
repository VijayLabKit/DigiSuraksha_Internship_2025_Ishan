# ips_core.py
from collections import defaultdict, deque
import re
import time

class Decision:
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"

class Verdict:
    def __init__(self, decision, reason=None, rule_id=None):
        self.decision = decision
        self.reason = reason
        self.rule_id = rule_id
    def __repr__(self):
        return f"Verdict({self.decision}, reason={self.reason}, rule={self.rule_id})"

class SlidingCounter:
    """Fixed window sliding counter per key to support rate-based rules."""
    def __init__(self, window_seconds=1.0):
        self.window = window_seconds
        self.events = defaultdict(deque)  # key -> deque[timestamps]

    def add(self, key, ts):
        q = self.events[key]
        q.append(ts)
        self._evict_old(q, ts)

    def count(self, key, now_ts):
        q = self.events[key]
        self._evict_old(q, now_ts)
        return len(q)

    def _evict_old(self, q, now_ts):
        w = self.window
        while q and (now_ts - q[0] > w):
            q.popleft()

class PortTracker:
    """Track unique destination ports per (src_ip, proto, flags signature) for scan detection."""
    def __init__(self, window_seconds=5.0):
        self.window = window_seconds
        self.map = defaultdict(deque)  # key -> deque[(ts, dport)]

    def add(self, key, ts, dport):
        q = self.map[key]
        q.append((ts, dport))
        self._evict_old(q, ts)

    def unique_ports(self, key, now_ts):
        q = self.map[key]
        self._evict_old(q, now_ts)
        return len(set(d for _, d in q))

    def _evict_old(self, q, now_ts):
        w = self.window
        while q and (now_ts - q[0][0] > w):
            q.popleft()

class HalfOpenTracker:
    """Track SYNs not followed by ACKs to spot SYN floods / half-open storms."""
    def __init__(self, window_seconds=10.0):
        self.window = window_seconds
        self.syns = defaultdict(deque)  # key=(dst_ip) -> deque[ts]
        self.acks = defaultdict(deque)  # key=(dst_ip) -> deque[ts]

    def record(self, dst_ip, ts, syn=False, ack=False):
        if syn:
            q = self.syns[dst_ip]
            q.append(ts)
            self._evict_old(q, ts)
        if ack:
            q = self.acks[dst_ip]
            q.append(ts)
            self._evict_old(q, ts)

    def syn_backlog(self, dst_ip, now_ts):
        self._evict_old(self.syns[dst_ip], now_ts)
        self._evict_old(self.acks[dst_ip], now_ts)
        # Approximation: backlog ~ SYNs - ACKs in window
        return max(0, len(self.syns[dst_ip]) - len(self.acks[dst_ip]))

    def _evict_old(self, q, now_ts):
        w = self.window
        while q and (now_ts - q[0] > w):
            q.popleft()

class IPSCore:
    """
    Core IPS logic. Feed it normalized events:
    event = {
      "ts": float, "src": str, "dst": str, "proto": "ICMP"/"TCP"/"UDP",
      "sport": int|None, "dport": int|None,
      "tcp_flags": {"S":bool,"A":bool,"F":bool,"R":bool,"P":bool,"U":bool,"NULL":bool},
      "payload": bytes|None
    }
    Returns a Verdict(ALLOW|BLOCK, reason, rule_id).
    """
    def __init__(self, cfg=None):
        cfg = cfg or {}
        # thresholds (tune for your environment)
        self.icmp_flood_rate = cfg.get("icmp_flood_rate", 100)    # per src per second
        self.syn_rate = cfg.get("syn_rate", 200)                  # per src per second
        self.syn_backlog_limit = cfg.get("syn_backlog_limit", 500) # per dst in 10s
        self.scan_unique_ports = cfg.get("scan_unique_ports", 20) # per 5s per src
        self.sql_sig_enabled = cfg.get("sql_sig_enabled", True)
        self.http_len_inspect_max = cfg.get("http_len_inspect_max", 2048)

        # state
        self.rate_icmp = SlidingCounter(window_seconds=1.0)
        self.rate_syn = SlidingCounter(window_seconds=1.0)
        self.scans = PortTracker(window_seconds=5.0)
        self.half_open = HalfOpenTracker(window_seconds=10.0)

        # signatures
        self.sql_regex = re.compile(
            rb"(' ?or ?1=1|union(?:\s+all)?\s+select|sleep\(|benchmark\(|xp_cmdshell|load_file\(|into\s+outfile)",
            re.I
        )

    def decide(self, event):
        ts = event["ts"]
        proto = event["proto"]
        src = event["src"]
        dst = event["dst"]

        # 1) ICMP ping flood
        if proto == "ICMP":
            self.rate_icmp.add(src, ts)
            count = self.rate_icmp.count(src, ts)
            if count > self.icmp_flood_rate:
                return Verdict(Decision.BLOCK, f"ICMP flood from {src} ({count}/s)", "ICMP_FLOOD")

            return Verdict(Decision.ALLOW)

        # 2) TCP-based checks
        if proto == "TCP":
            flags = event.get("tcp_flags") or {}
            syn = flags.get("S", False) and not flags.get("A", False)
            ack = flags.get("A", False)
            fin = flags.get("F", False)
            psh = flags.get("P", False)
            rst = flags.get("R", False)
            urg = flags.get("U", False)
            null = flags.get("NULL", False)
            dport = event.get("dport")

            # Track SYNs/ACKs for half-open detection
            if syn:
                self.rate_syn.add(src, ts)
                syn_rate = self.rate_syn.count(src, ts)
                if syn_rate > self.syn_rate:
                    return Verdict(Decision.BLOCK, f"SYN flood from {src} ({syn_rate}/s)", "SYN_FLOOD")

            self.half_open.record(dst, ts, syn=syn, ack=ack)
            backlog = self.half_open.syn_backlog(dst, ts)
            if backlog > self.syn_backlog_limit:
                return Verdict(Decision.BLOCK, f"Half-open connections backlog @ {dst} ~{backlog}", "HALF_OPEN")

            # Simple scan detection: SYN/NULL/FIN rapidly to many ports
            scan_key = (src, "TCP", self._flags_sig(flags))
            if dport is not None:
                self.scans.add(scan_key, ts, dport)
                uniq = self.scans.unique_ports(scan_key, ts)
                if uniq >= self.scan_unique_ports and (syn or fin or null or (not syn and not ack and not rst and not psh and not urg and not fin)):
                    return Verdict(Decision.BLOCK, f"Port scan from {src} ({uniq} ports/5s)", "PORT_SCAN")

            # Suspicious HTTP payloads: SQLi patterns
            payload = event.get("payload") or b""
            if payload and self.sql_sig_enabled:
                sample = payload[: self.http_len_inspect_max]
                if self.sql_regex.search(sample):
                    return Verdict(Decision.BLOCK, f"Suspicious HTTP payload (SQLi pattern) from {src}", "HTTP_SQLI")

            return Verdict(Decision.ALLOW)

        # 3) UDP: (simple scan heuristic on unique dports)
        if proto == "UDP":
            dport = event.get("dport")
            scan_key = (src, "UDP", "UDP")
            if dport is not None:
                self.scans.add(scan_key, ts, dport)
                uniq = self.scans.unique_ports(scan_key, ts)
                if uniq >= self.scan_unique_ports:
                    return Verdict(Decision.BLOCK, f"UDP scan from {src} ({uniq} ports/5s)", "UDP_SCAN")
            return Verdict(Decision.ALLOW)

        # default
        return Verdict(Decision.ALLOW)

    @staticmethod
    def _flags_sig(flags):
        order = ["S","A","F","R","P","U","NULL"]
        return "".join(k for k in order if flags.get(k, False))
