# main.py
import argparse
from ips_core import IPSCore
from rules import DEFAULT_CFG
from adapters import run_pcap, run_live
from utils import pretty_cfg

def parse_args():
    ap = argparse.ArgumentParser(description="Mini Network IPS (demo)")
    ap.add_argument("--pcap", help="Path to PCAP file for offline analysis")
    ap.add_argument("--live", help="Interface for live sniff, e.g. eth0")
    ap.add_argument("--print-allowed", action="store_true", help="Log allowed traffic too (pcap mode)")
    ap.add_argument("--icmp-rate", type=int, default=DEFAULT_CFG["icmp_flood_rate"])
    ap.add_argument("--syn-rate", type=int, default=DEFAULT_CFG["syn_rate"])
    ap.add_argument("--syn-backlog", type=int, default=DEFAULT_CFG["syn_backlog_limit"])
    ap.add_argument("--scan-ports", type=int, default=DEFAULT_CFG["scan_unique_ports"])
    ap.add_argument("--no-sqli", action="store_true", help="Disable SQLi signature check")
    return ap.parse_args()

def build_cfg(args):
    return {
        "icmp_flood_rate": args.icmp_rate,
        "syn_rate": args.syn_rate,
        "syn_backlog_limit": args.syn_backlog,
        "scan_unique_ports": args.scan_ports,
        "sql_sig_enabled": not args.no_sqli,
        "http_len_inspect_max": DEFAULT_CFG["http_len_inspect_max"],
    }

def main():
    args = parse_args()
    cfg = build_cfg(args)
    print(pretty_cfg(cfg))
    ips = IPSCore(cfg)

    if args.pcap:
        run_pcap(args.pcap, ips, print_allowed=args.print_allowed)
    elif args.live:
        run_live(args.live, ips)
    else:
        print("Provide --pcap <file> or --live <iface>")

if __name__ == "__main__":
    main()
