#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           Custom ICMP / Raw Packet Crafter                   ║
║  Craft IP/ICMP or raw packets with full field control        ║
╚══════════════════════════════════════════════════════════════╝

  Bit · Byte · Hex quick reference
  ─────────────────────────────────
   4 bit  = <1 byte  =  1 hex char
   8 bit  =  1 byte  =  2 hex chars
  16 bit  =  2 bytes =  4 hex chars
  32 bit  =  4 bytes =  8 hex chars
"""

import random, string, time
import scapy.all as scapy
from scapy.utils import checksum
from scapy.all import IP, ICMP, Raw
from scapy.layers.l2 import Ether

DEFAULT_PAYLOAD_LEN = 500

# ─────────────────────────────────────────────────────────────
#  Utility helpers
# ─────────────────────────────────────────────────────────────

def src_ip():
    try:    return scapy.get_if_addr(scapy.conf.iface)
    except: return "127.0.0.1"

def section(title):
    print(f"\n{'─'*60}\n  {title}\n{'─'*60}")

def prompt(name, bits, def_hex, def_bin, def_dec, lo=None, hi=None, note=None):
    lo_s = f"  min: h={hex(lo)[2:].zfill(bits//4 or 1)}  d={lo}" if lo is not None else ""
    hi_s = f"  max: h={hex(hi)[2:].zfill(bits//4 or 1)}  d={hi}" if hi is not None else ""
    nt_s = f"\n  note: {note}"                                     if note else ""
    hdr  = f"\n{name}  [{bits} bit = {bits//8 or '<1'} byte = {bits//4 or '<1'} hex]"
    dfl  = f"  default → hex={def_hex}  bin={def_bin}  dec={def_dec}"
    return input(f"{hdr}\n{dfl}{lo_s}{hi_s}{nt_s}\n  → ").strip()

def parse_num(s, default, name, lo=None, hi=None):
    if not s: return default
    s = s.strip().replace(" ", "").lower()
    for base in (10, 16, 2):
        try:
            v = int(s.replace("0x", ""), base) if base == 16 else int(s, base)
            if (lo is not None and v < lo) or (hi is not None and v > hi):
                print(f"  ⚠  {name}={v} is outside standard range → using anyway")
            return v
        except ValueError:
            pass
    print(f"  ✗  Invalid {name} → using default {default}")
    return default

def hex_to_bytes(s):
    clean = s.replace(" ", "").replace("0x", "")
    if not clean or not all(c in "0123456789abcdefABCDEF" for c in clean):
        return None
    try:    return bytes.fromhex(clean)
    except: return None

# ─────────────────────────────────────────────────────────────
#  IP header helpers
# ─────────────────────────────────────────────────────────────

def ip_chksum(ver, ihl, tos, tlen, id_, ff, ttl, proto, src, dst, opts=b''):
    """RFC 791 one's complement checksum over the IP header (opts always included)."""
    h = bytearray()
    h += bytes([(ver<<4)|ihl, tos])
    h += tlen.to_bytes(2,'big') + id_.to_bytes(2,'big') + ff.to_bytes(2,'big')
    h += bytes([ttl, proto, 0, 0]) + src + dst + opts
    s = 0
    for i in range(0, len(h), 2):
        w = (h[i]<<8) + (h[i+1] if i+1 < len(h) else 0)
        s = (s+w & 0xffff) + ((s+w) >> 16)
    return ~s & 0xffff

def build_ip_hdr(ver, ihl, tos, tlen, id_, ff, ttl, proto, src, dst, opts, ck):
    h = bytearray([(ver<<4)|ihl, tos])
    h += tlen.to_bytes(2,'big') + id_.to_bytes(2,'big') + ff.to_bytes(2,'big')
    h += bytes([ttl, proto, (ck>>8)&0xff, ck&0xff])
    h += src + dst + opts
    return bytes(h)

# ─────────────────────────────────────────────────────────────
#  Network helpers
# ─────────────────────────────────────────────────────────────

def resolve_mac(dst, src):
    lmac = scapy.get_if_hwaddr(scapy.conf.iface)
    _, _, nh = scapy.conf.route.route(dst)
    target = dst if nh in ("0.0.0.0", src) else nh
    print(f"  Resolving MAC for {target} ...")
    try:
        mac = scapy.getmacbyip(target)
        if mac:
            print(f"  ✓  MAC: {mac}")
            return lmac, mac
    except Exception as e:
        print(f"  ✗  MAC error: {e}")
    print("  →  fallback to broadcast")
    return lmac, "ff:ff:ff:ff:ff:ff"

def send_frame(ip_bytes, lmac, rmac, timeout, wait_reply=False):
    pkt = Ether(src=lmac, dst=rmac, type=0x0800) / Raw(load=ip_bytes)
    if wait_reply:
        return scapy.srp(pkt, timeout=timeout, verbose=0, iface=scapy.conf.iface)
    scapy.sendp(pkt, verbose=0, iface=scapy.conf.iface)
    return None, None

# ─────────────────────────────────────────────────────────────
#  Common input helpers
# ─────────────────────────────────────────────────────────────

def ask_padding():
    if input("\n  Add padding bytes? (y/n) [n]: ").strip().lower() not in ('y','yes'):
        return b''
    cnt = max(1, min(100, int(input("  Count [4]: ") or 4)))
    b   = int((input("  Byte hex [00]: ").strip() or "00"), 16) & 0xFF
    print(f"  →  {cnt} × 0x{b:02x}")
    return bytes([b]) * cnt

def ask_send_params():
    count    = int(input("\n  Packets     [1]:   ") or 1)
    interval = float(input("  Interval s  [1]:   ") or 1)
    timeout  = float(input("  Timeout s   [2]:   ") or 2)
    if count == 1 or interval >= 0.5:
        wait = input("  Wait for reply? (y/n) [y]: ").strip().lower() not in ('n','no')
    else:
        print("  →  High-speed burst mode: fire-and-forget (no per-packet reply wait)")
        wait = False
    return count, interval, timeout, wait

# ─────────────────────────────────────────────────────────────
#  Payload generator
# ─────────────────────────────────────────────────────────────

def gen_payload(n, ptype, pat=None):
    if n <= 0: return b''

    if ptype == 1:
        return bytes(random.randint(0,1) for _ in range(n))

    if ptype == 2:
        return bytes(random.randint(0,255) for _ in range(n))

    if ptype == 3:
        b = pat if isinstance(pat, int) else random.randint(0,255)
        print(f"  →  repeat 0x{b:02x}")
        return bytes([b]) * n

    if ptype == 4:
        buf, v = bytearray(), 0
        for _ in range(n):
            buf.append(v % 256)
            op = random.choice(['+2','*2','/2','nop'])
            if   op == '+2':       v += 2
            elif op == '*2':       v *= 2
            elif op == '/2' and v: v //= 2
        return bytes(buf)

    if ptype == 5:
        pool = (string.ascii_letters + string.digits + string.punctuation).encode()
        return bytes(random.choice(pool) for _ in range(n))

    if ptype == 6:
        bs = ''.join(random.choice('01') for _ in range(n*8))
        for _ in range(random.randint(2,6)):
            p  = random.randint(0, n*8-100)
            rl = random.randint(16, 80)
            bs = bs[:p] + random.choice('01')*rl + bs[p+rl:]
        bs  = bs[:n*8]
        buf = bytearray(int(bs[j:j+8].ljust(8,'0'), 2) for j in range(0, len(bs), 8))
        print("  →  bit stream pattern")
        return bytes(buf)

    if ptype == 7:
        pair = random.choice([(0x55,0xAA),(0xA5,0x5A),(0xFF,0x00),
                               (0xF0,0x0F),(0xCC,0x33),(0xAB,0xCD)])
        print(f"  →  hex-pair {pair[0]:02X} {pair[1]:02X} repeating")
        return bytes(pair[j%2] for j in range(n))

    if ptype == 8:
        raw = input("  Custom hex payload: ").strip()
        b   = hex_to_bytes(raw)
        if not b:
            print("  ✗  Invalid hex → falling back to random bytes")
            return bytes(random.randint(0,255) for _ in range(n))
        b = b[:n] if len(b) >= n else (b * ((n+len(b)-1)//len(b)))[:n]
        print(f"  →  custom payload {len(b)}B")
        return b

    return b''

# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    print(__doc__)

    # ── IP Header ────────────────────────────────────────────
    section("IP Header")

    version = parse_num(prompt("Version", 4, "4","0100","4", lo=4, hi=4), 4, "Version")

    ihl     = parse_num(prompt("IHL", 4, "5","0101","5",
                               lo=5, hi=15,
                               note="5=20B(base only)  6=24B  7=28B ... 15=60B  |  "
                                    "max IHL=15 → 60B total = 20B base + 40B options"),
                        5, "IHL")

    dscp    = parse_num(prompt("DSCP", 6, "00","000000","0", lo=0, hi=63),  0, "DSCP")
    ecn     = parse_num(prompt("ECN",  2, "00","00","0",     lo=0, hi=3),   0, "ECN")
    ttl     = parse_num(prompt("TTL",  8, "40","01000000","64",
                               lo=1, hi=255, note="1 byte  |  common: 64 (Linux) 128 (Windows)"),
                        64, "TTL")

    print("""
  Protocol number reference (8 bit = 1 byte = 2 hex chars)
  ┌──────┬──────┬─────────────────────────────────────────┐
  │ dec  │ hex  │ protocol                                │
  ├──────┼──────┼─────────────────────────────────────────┤
  │   1  │ 0x01 │ ICMP   Internet Control Message        │
  │   2  │ 0x02 │ IGMP   Internet Group Management       │
  │   4  │ 0x04 │ IPv4   IP-in-IP encapsulation          │
  │   6  │ 0x06 │ TCP    Transmission Control Protocol   │
  │  17  │ 0x11 │ UDP    User Datagram Protocol          │
  │  41  │ 0x29 │ IPv6   IPv6 encapsulation              │
  │  47  │ 0x2F │ GRE    Generic Routing Encapsulation   │
  │  50  │ 0x32 │ ESP    IPsec Encap Security Payload    │
  │  51  │ 0x33 │ AH     IPsec Authentication Header     │
  │  58  │ 0x3A │ ICMPv6 ICMP for IPv6                   │
  │  89  │ 0x59 │ OSPF   Open Shortest Path First        │
  │ 132  │ 0x84 │ SCTP   Stream Control Transmission     │
  └──────┴──────┴─────────────────────────────────────────┘""")

    proto   = parse_num(prompt("Proto", 8, "01","00000001","1",
                               lo=0, hi=255, note="1 byte  |  see table above"),
                        1, "Proto")

    ip_id   = parse_num(prompt("ID", 16, "0000","0"*16,"0",
                               lo=0, hi=65535, note="2 bytes  |  fragment identification"),
                        0, "ID")

    src = input(f"\n  Src IP  [{src_ip()}]: ").strip() or src_ip()
    dst = input(  "  Dst IP  [8.8.8.8]:  ").strip() or "8.8.8.8"

    # ── IP Options ───────────────────────────────────────────
    print("""
  IP Options
  ┌─────────────────────────────────────────────────────┐
  │  min  =  4B  ( 8 hex chars)                         │
  │  max  = 40B  (80 hex chars)                         │
  │  step =  4B  (must be multiple of 4 — one IHL word) │
  │  valid sizes: 4 8 12 16 20 24 28 32 36 40 bytes     │
  │  non-multiples are auto zero-padded to next 4B      │
  └─────────────────────────────────────────────────────┘""")

    ip_opts = b''
    if input("  Add IP options? (y/n) [n]: ").strip().lower() in ('y','yes'):
        h = input("  Options hex → ").strip().replace(" ","").replace("0x","").upper()
        if h and all(c in "0123456789ABCDEF" for c in h):
            try:
                ip_opts = bytes.fromhex(h)
                if len(ip_opts) > 40:
                    print(f"  ⚠  Exceeds max 40B (got {len(ip_opts)}B) → truncating to 40B")
                    ip_opts = ip_opts[:40]
                pad = (4 - len(ip_opts) % 4) % 4
                if pad:
                    ip_opts += b'\x00' * pad
                    print(f"  →  Auto-padded +{pad}B → {len(ip_opts)}B: {ip_opts.hex().upper()}")
                else:
                    print(f"  ✓  Accepted {len(ip_opts)}B: {h}")

                needed_ihl = 5 + len(ip_opts) // 4
                if needed_ihl != ihl:
                    print(f"  ⚠  IHL conflict: you set IHL={ihl} ({ihl*4}B) but "
                          f"{len(ip_opts)}B options require IHL={needed_ihl} ({needed_ihl*4}B)")
                    print(f"     1. Auto-adjust IHL to {needed_ihl}  (correct)")
                    print(f"     2. Keep IHL={ihl}  (intentional mismatch on wire)")
                    ihl_choice = input("  → [1]: ").strip() or "1"
                    if ihl_choice == "2":
                        print(f"  →  Keeping IHL={ihl} ({ihl*4}B)  — mismatch intentional")
                    else:
                        ihl = needed_ihl
                        print(f"  →  IHL auto-adjusted to {ihl} ({ihl*4}B)")
                else:
                    ihl = needed_ihl
                print(f"  →  IHL={ihl}  ({ihl*4}B total = 20B base + {len(ip_opts)}B options)"
                      f"  [IHL max=15=60B]")
            except Exception as e:
                print(f"  ✗  Error: {e} → no options added")
        else:
            print("  ✗  Invalid hex → no options added")

    SRC, DST, tos, ff = scapy.inet_aton(src), scapy.inet_aton(dst), (dscp<<2)|ecn, 0x0000

    # ── Payload size (first ask) ──────────────────────────────
    print()
    _pl = input(f"  ICMP Payload size B  [default {DEFAULT_PAYLOAD_LEN}B | 0 = empty payload]: ").strip()
    payload_len = int(_pl) if _pl else DEFAULT_PAYLOAD_LEN
    payload_len = max(0, payload_len)
    print(f"  →  {'empty payload' if payload_len == 0 else str(payload_len)+'B'}  (can override again inside ICMP header section)")

    # ── IP Checksum ──────────────────────────────────────────
    # ip_opts_for_ck  = slice of ip_opts used for checksum calculation only.
    # ip_opts         = full options always written to the wire unchanged.
    ip_opts_for_ck = ip_opts   # default: full options

    preview   = ip_chksum(version, ihl, tos, ihl*4+8+payload_len,
                          ip_id, ff, ttl, proto, SRC, DST, ip_opts)
    opts_info = f"{len(ip_opts)}B = {ip_opts.hex().upper()}" if ip_opts else "none"
    print(f"\n  ── IP Checksum preview ──")
    print(f"     calc  = 0x{preview:04x}  (using all {len(ip_opts)}B opts)")
    print(f"     ID    = 0x{ip_id:04x}")
    print(f"     opts  = {opts_info}")

    cs_in = input(f"\n  Desired IP checksum  [Enter = auto  |  or type custom hex]: ").strip()
    if cs_in:
        try:
            ip_ck     = int(cs_in.replace("0x",""), 16) & 0xFFFF
            ip_custom = True
            print(f"  →  custom 0x{ip_ck:04x}")
        except:
            print("  ✗  Invalid → using calculated value")
            ip_custom = False
    else:
        ip_custom = False

    if not ip_custom and len(ip_opts) > 0:
        ck_scope = input(f"  Options bytes for checksum  [0-{len(ip_opts)}, Enter = all {len(ip_opts)}B]: ").strip()
        try:    n_ck = max(0, min(len(ip_opts), int(ck_scope))) if ck_scope else len(ip_opts)
        except: n_ck = len(ip_opts)
        ip_opts_for_ck = ip_opts[:n_ck]
        ip_ck = ip_chksum(version, ihl, tos, ihl*4+8+payload_len,
                          ip_id, ff, ttl, proto, SRC, DST, ip_opts_for_ck)
        print(f"  →  0x{ip_ck:04x}  (20B + {n_ck}B opts used for checksum)")
    elif not ip_custom:
        ip_ck = preview
        print(f"  →  0x{ip_ck:04x}")

    # ── Protocol selection ───────────────────────────────────
    section("Protocol")
    print("  1.  ICMP")
    print("  2.  Raw hex  (bytes placed after IP header, uses proto field set above)")
    print("  3.  IP Raw payload  (reserved / non-standard proto — bare IP + raw body)")
    proto_sel = (input("\n  → [1]: ").strip() or "1")
    use_raw      = (proto_sel == "2")
    use_ip_raw   = (proto_sel == "3")

    # ════════════════════════════════════════════════════════
    #  RAW MODE  (option 2)
    # ════════════════════════════════════════════════════════
    if use_raw:
        section("Raw Payload")
        print("  Enter hex bytes placed directly after the IP header.")
        print("  Any case accepted: deadBEEF  /  DEADBEEF  /  deadbeef\n")

        raw_in    = input("  Raw hex → ").strip()
        raw_bytes = hex_to_bytes(raw_in)
        if raw_bytes is None:
            print("  ✗  Invalid hex → empty payload")
            raw_bytes, raw_in = b'', ""
        else:
            print(f"  ✓  Accepted: {raw_in}  ({len(raw_bytes)}B)")

        padding = ask_padding()
        count, interval, timeout, wait = ask_send_params()
        body, cur_id = raw_bytes + padding, ip_id

        print(f"\n  Sending {count} packet(s) to {dst} ...\n")
        lmac, rmac = resolve_mac(dst, src)

        for i in range(count):
            tlen = ihl*4 + len(body)
            ck   = ip_ck if ip_custom else ip_chksum(
                       version, ihl, tos, tlen, cur_id, ff, ttl, proto, SRC, DST, ip_opts_for_ck)
            hdr  = build_ip_hdr(version, ihl, tos, tlen, cur_id, ff, ttl, proto, SRC, DST, ip_opts, ck)
            send_frame(hdr + body, lmac, rmac, timeout, wait)
            print(f"  [{i+1:>4}/{count}]  RAW  {len(raw_bytes)}B  "
                  f"IPck=0x{ck:04x}  ID=0x{cur_id:04x}  hex={raw_in}")
            cur_id = (cur_id + 1) % 65536
            if i < count-1: time.sleep(interval)

        print("\n  Done.")
        return

    # ════════════════════════════════════════════════════════
    #  IP RAW PAYLOAD MODE  (option 3)
    #  Reserved / non-standard protocol number + bare raw body
    #  No ICMP/TCP/UDP structure — pure IP header + user bytes
    # ════════════════════════════════════════════════════════
    if use_ip_raw:
        section("IP Raw Payload  (reserved / non-standard protocol)")
        print("  Reserved / unassigned protocol numbers (suggestions):")
        print("  ┌──────┬──────┬────────────────────────────────────────────┐")
        print("  │ dec  │ hex  │ status                                     │")
        print("  ├──────┼──────┼────────────────────────────────────────────┤")
        print("  │   0  │ 0x00 │ HOPOPT  (reserved, rarely used)            │")
        print("  │  61  │ 0x3D │ any host internal protocol (unassigned)    │")
        print("  │  63  │ 0x3F │ any local network (unassigned)             │")
        print("  │ 143  │ 0x8F │ unassigned                                 │")
        print("  │ 253  │ 0xFD │ RFC 3692 experiment / testing              │")
        print("  │ 254  │ 0xFE │ RFC 3692 experiment / testing              │")
        print("  │ 255  │ 0xFF │ reserved                                   │")
        print("  └──────┴──────┴────────────────────────────────────────────┘")
        print("  (any value 0-255 accepted — use whatever proto number you want)\n")

        ip_raw_proto = parse_num(
            prompt("IP Proto for raw payload", 8, "FD","11111101","253",
                   lo=0, hi=255,
                   note="reserved suggestions: 61 63 143 253 254 255"),
            253, "IP proto")

        print("\n  Enter the raw IP payload bytes (the entire body after the IP header).")
        print("  Any case: deadBEEF / DEADBEEF / deadbeef\n")
        raw_in    = input("  Raw hex → ").strip()
        raw_bytes = hex_to_bytes(raw_in)
        if raw_bytes is None:
            print("  ✗  Invalid hex → empty payload")
            raw_bytes, raw_in = b'', ""
        else:
            print(f"  ✓  Accepted: {raw_in}  ({len(raw_bytes)}B)")

        padding = ask_padding()
        count, interval, timeout, wait = ask_send_params()
        body, cur_id = raw_bytes + padding, ip_id

        print(f"\n  Sending {count} packet(s) to {dst}  proto={ip_raw_proto} (0x{ip_raw_proto:02x}) ...\n")
        lmac, rmac = resolve_mac(dst, src)

        for i in range(count):
            tlen = ihl*4 + len(body)
            # Recalculate IP checksum using the user-chosen proto override
            ck   = ip_ck if ip_custom else ip_chksum(
                       version, ihl, tos, tlen, cur_id, ff, ttl, ip_raw_proto, SRC, DST, ip_opts_for_ck)
            hdr  = build_ip_hdr(version, ihl, tos, tlen, cur_id, ff, ttl,
                                ip_raw_proto, SRC, DST, ip_opts, ck)
            send_frame(hdr + body, lmac, rmac, timeout, wait)
            print(f"  [{i+1:>4}/{count}]  IP-RAW  proto={ip_raw_proto}(0x{ip_raw_proto:02x})  "
                  f"{len(raw_bytes)}B  IPck=0x{ck:04x}  ID=0x{cur_id:04x}")
            cur_id = (cur_id + 1) % 65536
            if i < count-1: time.sleep(interval)

        print("\n  Done.")
        return

    # ════════════════════════════════════════════════════════
    #  ICMP MODE
    # ════════════════════════════════════════════════════════
    section("ICMP Header")
    print("  Type / Code reference")
    print("  ┌──────┬──────┬────────────────────────────────────────┐")
    print("  │ type │ code │ meaning                                │")
    print("  ├──────┼──────┼────────────────────────────────────────┤")
    print("  │   0  │   0  │ Echo Reply                             │")
    print("  │   3  │ 0-15 │ Destination Unreachable                │")
    print("  │   8  │   0  │ Echo Request (ping)                    │")
    print("  │  11  │   0  │ Time Exceeded (TTL expired)            │")
    print("  │  12  │   0  │ Parameter Problem                      │")
    print("  └──────┴──────┴────────────────────────────────────────┘\n")

    itype = parse_num(prompt("Type", 8, "08","00001000","8",  lo=0, hi=255, note="1 byte"), 8, "Type")
    icode = parse_num(prompt("Code", 8, "00","00000000","0",  lo=0, hi=255, note="1 byte"), 0, "Code")
    iid   = parse_num(prompt("ID",  16, "0001","0"*15+"1","1",lo=0, hi=65535, note="2 bytes"), 1, "ID")
    seqb  = parse_num(prompt("Seq", 16, "0001","0"*15+"1","1",lo=0, hi=65535, note="2 bytes"), 1, "Seq")

    # ICMP checksum
    ick_in = input("\n  ICMP checksum  [Enter = auto  |  or type custom hex]: ").strip()
    icmp_custom, icmp_ck_val, icmp_extra = bool(ick_in), None, 0
    if icmp_custom:
        try:
            icmp_ck_val = int(ick_in.replace("0x",""), 16) & 0xFFFF
            print(f"  →  custom 0x{icmp_ck_val:04x}")
        except:
            print("  ✗  Invalid → auto")
            icmp_custom = False
    else:
        if input("  Extra bytes in ICMP checksum? (y/n) [n]: ").strip().lower() in ('y','yes'):
            try: icmp_extra = max(0, min(100, int(input("  Extra count [0]: ") or 0)))
            except: pass
        print(f"  →  auto{f'  +{icmp_extra}B extra' if icmp_extra else ''}")

    # Payload size (second ask — overrides first)
    cur_pl_label = 'empty' if payload_len == 0 else f'{payload_len}B'
    print(f"\n  Payload size is currently {cur_pl_label}  (set earlier)")
    pl_ov = input(f"  ICMP Payload size B  [Enter = keep {cur_pl_label}  |  0 = empty  |  or type new size]: ").strip()
    if pl_ov:
        try:
            payload_len = max(0, int(pl_ov))
            print(f"  →  {'empty payload' if payload_len == 0 else str(payload_len)+'B'}")
        except:
            print(f"  ✗  Invalid → keeping {cur_pl_label}")
    else:
        print(f"  →  keeping {cur_pl_label}")

    # Payload type — skip entirely if empty
    ptype, pat = 5, None
    if payload_len > 0:
        print("""
  Payload type
  ┌───┬──────────────────────────────────────────────────┐
  │ 1 │ random bits     (0 or 1 per byte)                │
  │ 2 │ random hex      (0x00–0xFF random bytes)         │
  │ 3 │ repeat pattern  (single byte repeated)           │
  │ 4 │ arithmetic      (incrementing with ops)          │
  │ 5 │ mixed           (printable ASCII + symbols)      │
  │ 6 │ bit stream      (random runs of 0s and 1s)       │
  │ 7 │ hex pair        (two-byte alternating pattern)   │
  │ 8 │ custom hex      (you supply the bytes)           │
  └───┴──────────────────────────────────────────────────┘""")
        try:    ptype = int(input("  → [5]: ").strip() or 5); ptype = ptype if 1<=ptype<=8 else 5
        except: ptype = 5
        if ptype == 3:
            try:    pat = int((input("  Pattern byte hex [AA]: ").strip() or "AA"), 16) & 0xFF
            except: pat = 0xAA
    else:
        print("  →  payload type skipped (empty payload)")

    padding = ask_padding()
    count, interval, timeout, wait = ask_send_params()

    print(f"\n  Sending {count} packet(s) to {dst} ...\n")
    lmac, rmac, cur_id = *resolve_mac(dst, src), ip_id

    for i in range(count):
        seq     = (seqb + i) % 65536
        payload = gen_payload(payload_len, ptype, pat)
        if not icmp_custom and icmp_extra:
            payload += b'\x00' * icmp_extra

        ih      = bytes(ICMP(type=itype, code=icode, id=iid, seq=seq))
        auto_ck = checksum(ih[:2] + b'\x00\x00' + ih[4:] + payload)
        fck     = icmp_ck_val if icmp_custom else auto_ck
        icmp_bytes = ih[:2] + fck.to_bytes(2,'big') + ih[4:] + payload + padding

        tlen    = ihl*4 + len(icmp_bytes)
        ip_ck_f = ip_ck if ip_custom else ip_chksum(
                      version, ihl, tos, tlen, cur_id, ff, ttl, proto, SRC, DST, ip_opts_for_ck)
        hdr     = build_ip_hdr(version, ihl, tos, tlen, cur_id, ff, ttl, proto, SRC, DST, ip_opts, ip_ck_f)

        ans, _  = send_frame(hdr + icmp_bytes, lmac, rmac, timeout, wait)
        print(f"  [{i+1:>4}/{count}]  {src} → {dst}"
              f"  ICMP {itype}/{icode}  id={iid}  seq={seq}"
              f"  pay={len(payload)}B  ICMPck=0x{fck:04x}  IPck=0x{ip_ck_f:04x}  ID=0x{cur_id:04x}")

        if wait:
            if ans:
                r_ip   = ans[0][1][IP]   if IP   in ans[0][1] else None
                r_icmp = ans[0][1][ICMP] if ICMP in ans[0][1] else None
                print(f"       ↳  reply from {r_ip.src if r_ip else '?'}")
                if r_icmp:
                    recv = bytes(r_icmp.payload) if r_icmp.payload else b''
                    ok   = checksum(bytes(r_icmp)) == 0
                    print(f"          ck={'OK' if ok else 'BAD'}"
                          f"  match={'YES' if recv==payload else f'NO  (sent {len(payload)}B  recv {len(recv)}B)'}")
            else:
                print("       ↳  no reply (timeout)")

        cur_id = (cur_id + 1) % 65536
        if i < count-1: time.sleep(interval)

    print("\n  Done.")

if __name__ == "__main__":
    try:    main()
    except KeyboardInterrupt: print("\n\n  Stopped.")
    except Exception as e:    print(f"\n  Error: {e}")
