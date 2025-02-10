#!/usr/bin/env python3
import sys

PMP_ENTRIES = 64

def count_trailing_ones(n):
    cnt = 0
    while n & 1:
        cnt += 1
        n //= 2
    return cnt

def load_pmp_config(fname):
    with open(fname, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]
    if len(lines) != 128:
        sys.exit("Config file must have 128 lines")
    configs = []
    for i in range(PMP_ENTRIES):
        try:
            val = int(lines[i], 16)
        except:
            sys.exit(f"Bad config on line {i+1}")
        configs.append({
            'read': bool(val & 0x01),
            'write': bool(val & 0x02),
            'exec': bool(val & 0x04),
            'mode': (val & 0x18) >> 3,
            'locked': bool(val & 0x80)
        })
    addrs = []
    for i in range(PMP_ENTRIES, 128):
        try:
            addrs.append(int(lines[i], 16))
        except:
            sys.exit(f"Bad addr on line {i+1}")
    return configs, addrs

def compute_range(idx, cfg, addrs):
    m = cfg['mode']
    if m == 1:  # TOR
        lo = 0 if idx == 0 else addrs[idx-1] << 2
        hi = addrs[idx] << 2
        return lo, hi
    elif m == 2:  # NA4
        base = addrs[idx] << 2
        return base, base + 4
    elif m == 3:  # NAPOT
        raw = addrs[idx]
        n = count_trailing_ones(raw)
        if n < 1: n = 1
        size = 8 << (n - 1)
        base = (raw & ~((1 << n) - 1)) << 2
        return base, base + size
    else:
        return None, None

def check_access(configs, addrs, addr, priv, op):
    any_enabled = False
    for i in range(PMP_ENTRIES):
        cfg = configs[i]
        if cfg['mode'] == 0:
            continue
        any_enabled = True
        lo, hi = compute_range(i, cfg, addrs)
        if lo <= addr < hi:
            if priv == 'M' and not cfg['locked']:
                return True
            if op == 'R' and cfg['read']: return True
            if op == 'W' and cfg['write']: return True
            if op == 'X' and cfg['exec']: return True
            return False
    return True if priv == 'M' else not any_enabled

def main():
    if len(sys.argv) != 5:
        sys.exit("Usage: pmp_check.py <config_file> <addr> <priv> <op>")
    config_file, addr_str, priv, op = sys.argv[1:5]
    priv, op = priv.upper(), op.upper()
    if not addr_str.startswith("0x"):
        sys.exit("Address must start with 0x")
    try:
        addr = int(addr_str, 16)
    except:
        sys.exit("Invalid address")
    if priv not in ('M', 'S', 'U'):
        sys.exit("Invalid privilege")
    if op not in ('R', 'W', 'X'):
        sys.exit("Invalid op")
    configs, addrs = load_pmp_config(config_file)
    allowed = check_access(configs, addrs, addr, priv, op)
    print("Access allowed" if allowed else "Access fault")

if __name__ == '__main__':
    main()
