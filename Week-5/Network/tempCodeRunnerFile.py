# tests/test_ips_core.py
import time
from ips.ips_core import IPSCore, Verdict

def mk_tcp(ts, src="1.1.1.1", dst="2.2.2.2", dport=80, flags=None, payload=b""):
    flags = flags or {}
    return {"ts": ts, "src": src, "dst": dst, "proto": "TCP",
            "sport": 12345, "dport": dport, "tcp_flags": flags, "payload": payload}

def mk_icmp(ts, src="1.1.1.1", dst="2.2.2.2"):
    return {"ts": ts, "src": src, "dst": dst, "proto": "ICMP",
            "sport": None, "dport": None, "tcp_flags": {}, "payload": b""}

def test_icmp_flood_blocks():
    ips = IPSCore({"icmp_flood_rate": 3, "syn_rate": 9999, "syn_backlog_limit": 9999, "scan_unique_ports": 9999, "sql_sig_enabled": True, "http_len_inspect_max": 1024})
    ts0 = 1000.0
    v1 = ips.decide(mk_icmp(ts0))
    v2 = ips.decide(mk_icmp(ts0 + 0.1))
    v3 = ips.decide(mk_icmp(ts0 + 0.2))
    v4 = ips.decide(mk_icmp(ts0 + 0.3))
    assert v4.decision == Verdict.BLOCK

def test_syn_flood_blocks():
    ips = IPSCore({"icmp_flood_rate": 9999, "syn_rate": 2, "syn_backlog_limit": 9999, "scan_unique_ports": 9999, "sql_sig_enabled": True, "http_len_inspect_max": 1024})
    ts0 = 1000.0
    f_syn = {"S": True, "A": False}
    assert ips.decide(mk_tcp(ts0, flags=f_syn)).decision == Verdict.ALLOW
    assert ips.decide(mk_tcp(ts0 + 0.1, flags=f_syn)).decision == Verdict.ALLOW
    assert ips.decide(mk_tcp(ts0 + 0.2, flags=f_syn)).decision == Verdict.BLOCK

def test_scan_blocks_on_unique_ports():
    ips = IPSCore({"icmp_flood_rate": 9999, "syn_rate": 9999, "syn_backlog_limit": 9999, "scan_unique_ports": 5, "sql_sig_enabled": True, "http_len_inspect_max": 1024})
    ts = 1000.0
    for i in range(1, 6):
        v = ips.decide(mk_tcp(ts + i*0.5, dport=1000+i, flags={"S": True}))
    assert v.decision == Verdict.BLOCK

def test_http_sqli_signature_blocks():
    ips = IPSCore({"icmp_flood_rate": 9999, "syn_rate": 9999, "syn_backlog_limit": 9999, "scan_unique_ports": 9999, "sql_sig_enabled": True, "http_len_inspect_max": 2048})
    ts = 2000.0
    payload = b"GET /?q=' OR 1=1-- HTTP/1.1\r\nHost: x\r\n\r\n"
    v = ips.decide(mk_tcp(ts, dport=80, flags={"A": True}, payload=payload))
    assert v.decision == Verdict.BLOCK
