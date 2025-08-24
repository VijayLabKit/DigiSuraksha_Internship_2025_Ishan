# utils.py
def pretty_cfg(cfg):
    lines = ["IPS Config:"]
    for k, v in sorted(cfg.items()):
        lines.append(f"  - {k}: {v}")
    return "\n".join(lines)
