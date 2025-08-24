# rules.py
DEFAULT_CFG = {
    "icmp_flood_rate": 100,       # ICMP echo per src per second
    "syn_rate": 200,              # TCP SYN per src per second
    "syn_backlog_limit": 500,     # Half-open backlog per dst in 10s
    "scan_unique_ports": 20,      # unique dports within 5s considered a scan
    "sql_sig_enabled": True,
    "http_len_inspect_max": 2048,
}
