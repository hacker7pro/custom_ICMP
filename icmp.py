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
from scapy.layers.inet import IP, ICMP, Raw
from scapy.layers.l2 import Ether

DEFAULT_PAYLOAD_LEN = 500

# ─────────────────────────────────────────────────────────────
#  ANSI colour palette
# ─────────────────────────────────────────────────────────────
R  = "\033[0m"          # reset
B  = "\033[1m"          # bold
CY = "\033[96m"         # cyan        — section titles / field names
GR = "\033[92m"         # green       — ok / accepted / sent
YL = "\033[93m"         # yellow      — defaults / notes / warnings
RD = "\033[91m"         # red         — errors / bad
MG = "\033[95m"         # magenta     — checksum values / hex data
BL = "\033[94m"         # blue        — IP addresses / MAC
DM = "\033[2m"          # dim         — table borders / dividers
WH = "\033[97m"         # bright white — prompt arrows / labels

def c(color, text): return f"{color}{text}{R}"

# ─────────────────────────────────────────────────────────────
#  Utility helpers
# ─────────────────────────────────────────────────────────────

def src_ip():
    try:    return scapy.get_if_addr(scapy.conf.iface)
    except: return "127.0.0.1"

def section(title):
    bar = c(DM, "─" * 60)
    print(f"\n{bar}\n  {c(B+CY, title)}\n{bar}")

def prompt(name, bits, def_hex, def_bin, def_dec, lo=None, hi=None, note=None):
    lo_s = f"  {c(DM,'min:')} h={c(MG, hex(lo)[2:].zfill(bits//4 or 1))}  d={c(YL,str(lo))}" if lo is not None else ""
    hi_s = f"  {c(DM,'max:')} h={c(MG, hex(hi)[2:].zfill(bits//4 or 1))}  d={c(YL,str(hi))}" if hi is not None else ""
    nt_s = f"\n  {c(DM,'note:')} {c(YL, note)}" if note else ""
    bit_info = c(DM, f"[{bits} bit = {bits//8 or '<1'} byte = {bits//4 or '<1'} hex]")
    hdr  = f"\n{c(B+CY, name)}  {bit_info}"
    dfl  = f"  {c(DM,'default →')} hex={c(MG,def_hex)}  bin={c(DM,def_bin)}  dec={c(YL,def_dec)}"
    return input(f"{hdr}\n{dfl}{lo_s}{hi_s}{nt_s}\n  {c(WH,'→')} ").strip()

def parse_num(s, default, name, lo=None, hi=None):
    if not s: return default
    s = s.strip().replace(" ", "").lower()
    for base in (10, 16, 2):
        try:
            v = int(s.replace("0x", ""), base) if base == 16 else int(s, base)
            if (lo is not None and v < lo) or (hi is not None and v > hi):
                print(f"  {c(YL,'⚠')}  {name}={v} is outside standard range {c(DM,'→ using anyway')}")
            return v
        except ValueError:
            pass
    print(f"  {c(RD,'✗')}  Invalid {name} {c(DM,f'→ using default {default}')}")
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
    print(f"  {c(DM,'Resolving MAC for')} {c(BL, target)} ...")
    try:
        mac = scapy.getmacbyip(target)
        if mac:
            print(f"  {c(GR,'✓')}  MAC: {c(BL, mac)}")
            return lmac, mac
    except Exception as e:
        print(f"  {c(RD,'✗')}  MAC error: {e}")
    print(f"  {c(YL,'→')}  fallback to broadcast")
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
    if input(f"\n  {c(CY,'Add padding bytes?')} (y/n) [n]: ").strip().lower() not in ('y','yes'):
        return b''
    cnt = max(1, min(100, int(input("  Count [4]: ") or 4)))
    b   = int((input("  Byte hex [00]: ").strip() or "00"), 16) & 0xFF
    print(f"  {c(GR,'→')}  {cnt} × {c(MG, f'0x{b:02x}')}")
    return bytes([b]) * cnt

def ask_send_params():
    count    = int(input(f"\n  {c(CY,'Packets')}     [1]:   ") or 1)
    interval = float(input(f"  {c(CY,'Interval s')}  [1]:   ") or 1)
    timeout  = float(input(f"  {c(CY,'Timeout s')}   [2]:   ") or 2)
    if count == 1 or interval >= 0.5:
        wait = input(f"  {c(CY,'Wait for reply?')} (y/n) [y]: ").strip().lower() not in ('n','no')
    else:
        print(f"  {c(YL,'→')}  High-speed burst mode: {c(DM,'fire-and-forget (no per-packet reply wait)')}")
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
        print(f"  {c(GR,'→')}  repeat {c(MG, f'0x{b:02x}')}")
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
        print(f"  {c(GR,'→')}  bit stream pattern")
        return bytes(buf)

    if ptype == 7:
        pair = random.choice([(0x55,0xAA),(0xA5,0x5A),(0xFF,0x00),
                               (0xF0,0x0F),(0xCC,0x33),(0xAB,0xCD)])
        print(f"  {c(GR,'→')}  hex-pair {c(MG, f'{pair[0]:02X} {pair[1]:02X}')} repeating")
        return bytes(pair[j%2] for j in range(n))

    if ptype == 8:
        b = hex_to_bytes(input(f"  {c(CY,'Custom hex payload')}: ").strip())
        if not b:
            print(f"  {c(RD,'✗')}  Invalid hex {c(DM,'→ falling back to random bytes')}")
            return bytes(random.randint(0,255) for _ in range(n))
        b = b[:n] if len(b) >= n else (b * ((n+len(b)-1)//len(b)))[:n]
        print(f"  {c(GR,'→')}  custom payload {c(YL, str(len(b))+'B')}")
        return b

    return b''

# ─────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────

def main():
    # Banner
    print(c(B+CY, """
╔══════════════════════════════════════════════════════════════╗
║           Custom ICMP / Raw Packet Crafter                   ║
║  Craft IP/ICMP or raw packets with full field control        ║
╚══════════════════════════════════════════════════════════════╝"""))
    print(c(DM,
        "  Bit·Byte·Hex: "
        "4bit=<1B=1hex  "
        "8bit=1B=2hex  "
        "16bit=2B=4hex  "
        "32bit=4B=8hex"))

    # ── IP Header ────────────────────────────────────────────
    section("IP Header")

    version = parse_num(prompt("Version", 4, "4","0100","4", lo=4, hi=4), 4, "Version")

    ihl = parse_num(prompt("IHL", 4, "5","0101","5",
                            lo=5, hi=15,
                            note="5=20B(base only)  6=24B  7=28B ... 15=60B  |  "
                                 "max IHL=15 → 60B total = 20B base + 40B options"),
                    5, "IHL")

    dscp = parse_num(prompt("DSCP", 6, "00","000000","0", lo=0, hi=63),  0, "DSCP")
    ecn  = parse_num(prompt("ECN",  2, "00","00","0",     lo=0, hi=3),   0, "ECN")
    ttl  = parse_num(prompt("TTL",  8, "40","01000000","64",
                             lo=1, hi=255, note="1 byte  |  common: 64 (Linux) 128 (Windows)"),
                     64, "TTL")

    dm = c(DM,"│"); hd = c(B+CY,"│")
    print(f"""
  {c(B+CY,'Protocol number reference')} {c(DM,'(8 bit = 1 byte = 2 hex chars)')}
  {c(DM,'┌──────┬──────┬─────────────────────────────────────────┐')}
  {hd} {c(YL,'dec ')} {dm} {c(YL,'hex ')} {dm} {c(CY,'protocol')}                                {hd}
  {c(DM,'├──────┼──────┼─────────────────────────────────────────┤')}
  {dm}   {c(GR,'1')}  {dm} {c(MG,'0x01')} {dm} ICMP   Internet Control Message        {dm}
  {dm}   {c(GR,'2')}  {dm} {c(MG,'0x02')} {dm} IGMP   Internet Group Management       {dm}
  {dm}   {c(GR,'4')}  {dm} {c(MG,'0x04')} {dm} IPv4   IP-in-IP encapsulation          {dm}
  {dm}   {c(GR,'6')}  {dm} {c(MG,'0x06')} {dm} TCP    Transmission Control Protocol   {dm}
  {dm}  {c(GR,'17')}  {dm} {c(MG,'0x11')} {dm} UDP    User Datagram Protocol          {dm}
  {dm}  {c(GR,'41')}  {dm} {c(MG,'0x29')} {dm} IPv6   IPv6 encapsulation              {dm}
  {dm}  {c(GR,'47')}  {dm} {c(MG,'0x2F')} {dm} GRE    Generic Routing Encapsulation   {dm}
  {dm}  {c(GR,'50')}  {dm} {c(MG,'0x32')} {dm} ESP    IPsec Encap Security Payload    {dm}
  {dm}  {c(GR,'51')}  {dm} {c(MG,'0x33')} {dm} AH     IPsec Authentication Header     {dm}
  {dm}  {c(GR,'58')}  {dm} {c(MG,'0x3A')} {dm} ICMPv6 ICMP for IPv6                   {dm}
  {dm}  {c(GR,'89')}  {dm} {c(MG,'0x59')} {dm} OSPF   Open Shortest Path First        {dm}
  {dm} {c(GR,'132')}  {dm} {c(MG,'0x84')} {dm} SCTP   Stream Control Transmission     {dm}
  {c(DM,'└──────┴──────┴─────────────────────────────────────────┘')}""")

    proto = parse_num(prompt("Proto", 8, "01","00000001","1",
                              lo=0, hi=255, note="1 byte  |  see table above"),
                      1, "Proto")

    ip_id = parse_num(prompt("ID", 16, "0000","0"*16,"0",
                              lo=0, hi=65535, note="2 bytes  |  fragment identification"),
                      0, "ID")

    src = input(f"\n  {c(CY,'Src IP')}  [{c(BL, src_ip())}]: ").strip() or src_ip()
    dst = input(f"  {c(CY,'Dst IP')}  [{c(BL,'8.8.8.8')}]:  ").strip() or "8.8.8.8"

    # ── IP Options ───────────────────────────────────────────
    print(f"""
  {c(B+CY,'IP Options')}
  {c(DM,'┌─────────────────────────────────────────────────────┐')}
  {c(DM,'│')}  min  =  {c(YL,' 4B')}  ({c(MG,' 8 hex chars')})                         {c(DM,'│')}
  {c(DM,'│')}  max  =  {c(YL,'40B')}  ({c(MG,'80 hex chars')})                         {c(DM,'│')}
  {c(DM,'│')}  step =   {c(YL,'4B')}  (must be multiple of 4 — one IHL word)  {c(DM,'│')}
  {c(DM,'│')}  valid: {c(GR,'4 8 12 16 20 24 28 32 36 40')} bytes             {c(DM,'│')}
  {c(DM,'│')}  non-multiples are {c(YL,'auto zero-padded')} to next 4B        {c(DM,'│')}
  {c(DM,'└─────────────────────────────────────────────────────┘')}""")

    ip_opts = b''
    if input(f"  {c(CY,'Add IP options?')} (y/n) [n]: ").strip().lower() in ('y','yes'):
        h = input(f"  {c(CY,'Options hex')} {c(WH,'→')} ").strip().replace(" ","").replace("0x","").upper()
        if h and all(ch in "0123456789ABCDEF" for ch in h):
            try:
                ip_opts = bytes.fromhex(h)
                if len(ip_opts) > 40:
                    print(f"  {c(YL,'⚠')}  Exceeds max 40B (got {len(ip_opts)}B) {c(DM,'→ truncating to 40B')}")
                    ip_opts = ip_opts[:40]
                pad = (4 - len(ip_opts) % 4) % 4
                if pad:
                    ip_opts += b'\x00' * pad
                    print(f"  {c(YL,'→')}  Auto-padded +{pad}B → {c(YL,str(len(ip_opts))+'B')}: {c(MG, ip_opts.hex().upper())}")
                else:
                    print(f"  {c(GR,'✓')}  Accepted {c(YL,str(len(ip_opts))+'B')}: {c(MG, h)}")

                needed_ihl = 5 + len(ip_opts) // 4
                if needed_ihl != ihl:
                    print(f"  {c(YL,'⚠')}  IHL conflict: you set {c(MG,f'IHL={ihl}')} ({ihl*4}B) but "
                          f"{len(ip_opts)}B options require {c(GR,f'IHL={needed_ihl}')} ({needed_ihl*4}B)")
                    print(f"     {c(GR,'1.')} Auto-adjust IHL to {c(GR,str(needed_ihl))}  {c(DM,'(correct)')}")
                    print(f"     {c(YL,'2.')} Keep IHL={c(YL,str(ihl))}  {c(DM,'(intentional mismatch on wire)')}")
                    ihl_choice = input(f"  {c(WH,'→')} [1]: ").strip() or "1"
                    if ihl_choice == "2":
                        print(f"  {c(YL,'→')}  Keeping {c(MG,f'IHL={ihl}')} ({ihl*4}B)  {c(DM,'— mismatch intentional')}")
                    else:
                        ihl = needed_ihl
                        print(f"  {c(GR,'→')}  IHL auto-adjusted to {c(MG, str(ihl))} ({ihl*4}B)")
                else:
                    ihl = needed_ihl
                print(f"  {c(DM,'→')}  IHL={c(MG,str(ihl))}  ({ihl*4}B = 20B base + {len(ip_opts)}B opts)  "
                      f"{c(DM,'[max IHL=15=60B]')}")
            except Exception as e:
                print(f"  {c(RD,'✗')}  Error: {e} {c(DM,'→ no options added')}")
        else:
            print(f"  {c(RD,'✗')}  Invalid hex {c(DM,'→ no options added')}")

    SRC, DST, tos, ff = scapy.inet_aton(src), scapy.inet_aton(dst), (dscp<<2)|ecn, 0x0000

    # ── Payload size (first ask) ──────────────────────────────
    print()
    _pl = input(f"  {c(CY,'ICMP Payload size B')}  [{c(YL,str(DEFAULT_PAYLOAD_LEN)+'B')} | {c(DM,'0 = empty payload')}]: ").strip()
    payload_len = int(_pl) if _pl else DEFAULT_PAYLOAD_LEN
    payload_len = max(0, payload_len)
    lbl = c(DM,'empty payload') if payload_len == 0 else c(YL, str(payload_len)+'B')
    print(f"  {c(GR,'→')}  {lbl}  {c(DM,'(can override again inside ICMP header section)')}")

    # ── IP Checksum ──────────────────────────────────────────
    ip_opts_for_ck = ip_opts
    preview   = ip_chksum(version, ihl, tos, ihl*4+8+payload_len,
                          ip_id, ff, ttl, proto, SRC, DST, ip_opts)
    opts_info = f"{c(YL,str(len(ip_opts))+'B')} = {c(MG, ip_opts.hex().upper())}" if ip_opts else c(DM,"none")
    print(f"\n  {c(B+CY,'── IP Checksum preview ──')}")
    print(f"     calc  = {c(MG, f'0x{preview:04x}')}")
    print(f"     ID    = {c(MG, f'0x{ip_id:04x}')}")
    print(f"     opts  = {opts_info}")

    cs_in = input(f"\n  {c(CY,'Desired IP checksum')}  [{c(DM,'Enter = auto')}  |  {c(DM,'or type custom hex')}]: ").strip()
    if cs_in:
        try:
            ip_ck     = int(cs_in.replace("0x",""), 16) & 0xFFFF
            ip_custom = True
            print(f"  {c(YL,'→')}  custom {c(MG, f'0x{ip_ck:04x}')}")
        except:
            print(f"  {c(RD,'✗')}  Invalid {c(DM,'→ using calculated value')}")
            ip_custom = False
    else:
        ip_custom = False

    if not ip_custom and len(ip_opts) > 0:
        ck_scope = input(f"  {c(CY,'Options bytes for checksum')}  [{c(DM,f'0-{len(ip_opts)}')} | {c(YL,f'Enter = all {len(ip_opts)}B')}]: ").strip()
        try:    n_ck = max(0, min(len(ip_opts), int(ck_scope))) if ck_scope else len(ip_opts)
        except: n_ck = len(ip_opts)
        ip_opts_for_ck = ip_opts[:n_ck]
        ip_ck = ip_chksum(version, ihl, tos, ihl*4+8+payload_len,
                          ip_id, ff, ttl, proto, SRC, DST, ip_opts_for_ck)
        print(f"  {c(GR,'→')}  {c(MG, f'0x{ip_ck:04x}')}  {c(DM, f'(20B + {n_ck}B opts used for checksum)')}")
    elif not ip_custom:
        ip_ck = preview
        print(f"  {c(GR,'→')}  {c(MG, f'0x{ip_ck:04x}')}")

    # ── Protocol selection ───────────────────────────────────
    section("Protocol")
    print(f"  {c(GR,'1.')}  {c(WH,'ICMP')}")
    print(f"  {c(GR,'2.')}  {c(WH,'Raw hex')}  {c(DM,'(bytes after IP header, uses proto field set above)')}")
    print(f"  {c(GR,'3.')}  {c(WH,'IP Raw payload')}  {c(DM,'(reserved / non-standard proto — bare IP + raw body)')}")
    proto_sel  = (input(f"\n  {c(WH,'→')} [1]: ").strip() or "1")
    use_raw    = (proto_sel == "2")
    use_ip_raw = (proto_sel == "3")

    # ════════════════════════════════════════════════════════
    #  RAW MODE  (option 2)
    # ════════════════════════════════════════════════════════
    if use_raw:
        section("Raw Payload")
        print(f"  Enter hex bytes placed directly after the IP header.")
        print(f"  {c(DM,'Any case accepted:')} {c(MG,'deadBEEF')} / {c(MG,'DEADBEEF')} / {c(MG,'deadbeef')}\n")

        raw_in    = input(f"  {c(CY,'Raw hex')} {c(WH,'→')} ").strip()
        raw_bytes = hex_to_bytes(raw_in)
        if raw_bytes is None:
            print(f"  {c(RD,'✗')}  Invalid hex {c(DM,'→ empty payload')}")
            raw_bytes, raw_in = b'', ""
        else:
            print(f"  {c(GR,'✓')}  Accepted: {c(MG, raw_in)}  ({c(YL, str(len(raw_bytes))+'B')})")

        padding = ask_padding()
        count, interval, timeout, wait = ask_send_params()
        body, cur_id = raw_bytes + padding, ip_id

        print(f"\n  {c(GR,'Sending')} {c(YL,str(count))} packet(s) to {c(BL,dst)} ...\n")
        lmac, rmac = resolve_mac(dst, src)

        for i in range(count):
            tlen = ihl*4 + len(body)
            ck   = ip_ck if ip_custom else ip_chksum(
                       version, ihl, tos, tlen, cur_id, ff, ttl, proto, SRC, DST, ip_opts_for_ck)
            hdr  = build_ip_hdr(version, ihl, tos, tlen, cur_id, ff, ttl, proto, SRC, DST, ip_opts, ck)
            send_frame(hdr + body, lmac, rmac, timeout, wait)
            print(f"  {c(DM,f'[{i+1:>4}/{count}]')}  {c(GR,'RAW')}  {c(YL,str(len(raw_bytes))+'B')}"
                  f"  IPck={c(MG,f'0x{ck:04x}')}  ID={c(MG,f'0x{cur_id:04x}')}"
                  f"  hex={c(DM, raw_in)}")
            cur_id = (cur_id + 1) % 65536
            if i < count-1: time.sleep(interval)

        print(f"\n  {c(GR+B,'Done.')}")
        return

    # ════════════════════════════════════════════════════════
    #  IP RAW PAYLOAD MODE  (option 3)
    # ════════════════════════════════════════════════════════
    if use_ip_raw:
        section("IP Raw Payload  (reserved / non-standard protocol)")
        dm = c(DM,"│")
        print(f"  {c(B+CY,'Reserved / unassigned protocol numbers (suggestions):')}")
        print(f"  {c(DM,'┌──────┬──────┬────────────────────────────────────────────┐')}")
        print(f"  {dm} {c(YL,'dec ')} {dm} {c(YL,'hex ')} {dm} {c(CY,'status')}                                     {dm}")
        print(f"  {c(DM,'├──────┼──────┼────────────────────────────────────────────┤')}")
        print(f"  {dm}   {c(GR,'0')}  {dm} {c(MG,'0x00')} {dm} HOPOPT  (reserved, rarely used)            {dm}")
        print(f"  {dm}  {c(GR,'61')}  {dm} {c(MG,'0x3D')} {dm} any host internal protocol (unassigned)    {dm}")
        print(f"  {dm}  {c(GR,'63')}  {dm} {c(MG,'0x3F')} {dm} any local network (unassigned)             {dm}")
        print(f"  {dm} {c(GR,'143')}  {dm} {c(MG,'0x8F')} {dm} unassigned                                 {dm}")
        print(f"  {dm} {c(GR,'253')}  {dm} {c(MG,'0xFD')} {dm} RFC 3692 experiment / testing              {dm}")
        print(f"  {dm} {c(GR,'254')}  {dm} {c(MG,'0xFE')} {dm} RFC 3692 experiment / testing              {dm}")
        print(f"  {dm} {c(GR,'255')}  {dm} {c(MG,'0xFF')} {dm} reserved                                   {dm}")
        print(f"  {c(DM,'└──────┴──────┴────────────────────────────────────────────┘')}")
        print(f"  {c(DM,'(any value 0-255 accepted)')}\n")

        ip_raw_proto = parse_num(
            prompt("IP Proto for raw payload", 8, "FD","11111101","253",
                   lo=0, hi=255, note="reserved suggestions: 61 63 143 253 254 255"),
            253, "IP proto")

        print(f"\n  {c(CY,'Enter the raw IP payload bytes')} {c(DM,'(entire body after IP header)')}")
        print(f"  {c(DM,'Any case:')} {c(MG,'deadBEEF')} / {c(MG,'DEADBEEF')} / {c(MG,'deadbeef')}\n")
        raw_in    = input(f"  {c(CY,'Raw hex')} {c(WH,'→')} ").strip()
        raw_bytes = hex_to_bytes(raw_in)
        if raw_bytes is None:
            print(f"  {c(RD,'✗')}  Invalid hex {c(DM,'→ empty payload')}")
            raw_bytes, raw_in = b'', ""
        else:
            print(f"  {c(GR,'✓')}  Accepted: {c(MG, raw_in)}  ({c(YL, str(len(raw_bytes))+'B')})")

        padding = ask_padding()
        count, interval, timeout, wait = ask_send_params()
        body, cur_id = raw_bytes + padding, ip_id

        print(f"\n  {c(GR,'Sending')} {c(YL,str(count))} packet(s) to {c(BL,dst)}"
              f"  proto={c(MG,str(ip_raw_proto))} ({c(MG,f'0x{ip_raw_proto:02x}')}) ...\n")
        lmac, rmac = resolve_mac(dst, src)

        for i in range(count):
            tlen = ihl*4 + len(body)
            ck   = ip_ck if ip_custom else ip_chksum(
                       version, ihl, tos, tlen, cur_id, ff, ttl, ip_raw_proto, SRC, DST, ip_opts_for_ck)
            hdr  = build_ip_hdr(version, ihl, tos, tlen, cur_id, ff, ttl,
                                ip_raw_proto, SRC, DST, ip_opts, ck)
            send_frame(hdr + body, lmac, rmac, timeout, wait)
            print(f"  {c(DM,f'[{i+1:>4}/{count}]')}  {c(GR,'IP-RAW')}"
                  f"  proto={c(MG,str(ip_raw_proto))}({c(MG,f'0x{ip_raw_proto:02x}')})"
                  f"  {c(YL,str(len(raw_bytes))+'B')}"
                  f"  IPck={c(MG,f'0x{ck:04x}')}  ID={c(MG,f'0x{cur_id:04x}')}")
            cur_id = (cur_id + 1) % 65536
            if i < count-1: time.sleep(interval)

        print(f"\n  {c(GR+B,'Done.')}")
        return

    # ════════════════════════════════════════════════════════
    #  ICMP MODE
    # ════════════════════════════════════════════════════════
    section("ICMP Header")
    dm = c(DM,"│")
    print(f"  {c(B+CY,'Type / Code reference')}")
    print(f"  {c(DM,'┌──────┬──────┬────────────────────────────────────────┐')}")
    print(f"  {dm} {c(YL,'type')} {dm} {c(YL,'code')} {dm} {c(CY,'meaning')}                                {dm}")
    print(f"  {c(DM,'├──────┼──────┼────────────────────────────────────────┤')}")
    print(f"  {dm}   {c(GR,'0')}  {dm}   {c(GR,'0')}  {dm} Echo Reply                             {dm}")
    print(f"  {dm}   {c(GR,'3')}  {dm} {c(GR,'0-15')} {dm} Destination Unreachable                {dm}")
    print(f"  {dm}   {c(GR,'8')}  {dm}   {c(GR,'0')}  {dm} Echo Request (ping)                    {dm}")
    print(f"  {dm}  {c(GR,'11')}  {dm}   {c(GR,'0')}  {dm} Time Exceeded (TTL expired)            {dm}")
    print(f"  {dm}  {c(GR,'12')}  {dm}   {c(GR,'0')}  {dm} Parameter Problem                      {dm}")
    print(f"  {c(DM,'└──────┴──────┴────────────────────────────────────────┘')}\n")

    itype = parse_num(prompt("Type", 8, "08","00001000","8",  lo=0, hi=255, note="1 byte"), 8, "Type")
    icode = parse_num(prompt("Code", 8, "00","00000000","0",  lo=0, hi=255, note="1 byte"), 0, "Code")
    iid   = parse_num(prompt("ID",  16, "0001","0"*15+"1","1",lo=0, hi=65535, note="2 bytes"), 1, "ID")
    seqb  = parse_num(prompt("Seq", 16, "0001","0"*15+"1","1",lo=0, hi=65535, note="2 bytes"), 1, "Seq")

    # ICMP checksum
    ick_in = input(f"\n  {c(CY,'ICMP checksum')}  [{c(DM,'Enter = auto')}  |  {c(DM,'or type custom hex')}]: ").strip()
    icmp_custom, icmp_ck_val, icmp_extra = bool(ick_in), None, 0
    if icmp_custom:
        try:
            icmp_ck_val = int(ick_in.replace("0x",""), 16) & 0xFFFF
            print(f"  {c(YL,'→')}  custom {c(MG, f'0x{icmp_ck_val:04x}')}")
        except:
            print(f"  {c(RD,'✗')}  Invalid {c(DM,'→ auto')}")
            icmp_custom = False
    else:
        if input(f"  {c(CY,'Extra bytes in ICMP checksum?')} (y/n) [n]: ").strip().lower() in ('y','yes'):
            try: icmp_extra = max(0, min(100, int(input("  Extra count [0]: ") or 0)))
            except: pass
        print(f"  {c(GR,'→')}  auto{c(YL, f'  +{icmp_extra}B extra') if icmp_extra else ''}")

    # Payload size (second ask)
    cur_pl_label = c(DM,'empty') if payload_len == 0 else c(YL, str(payload_len)+'B')
    print(f"\n  Payload size is currently {cur_pl_label}  {c(DM,'(set earlier)')}")
    pl_ov = input(f"  {c(CY,'ICMP Payload size B')}  [{c(DM,'Enter = keep')} {cur_pl_label}  |  {c(DM,'0 = empty')}  |  {c(DM,'or new size')}]: ").strip()
    if pl_ov:
        try:
            payload_len = max(0, int(pl_ov))
            lbl2 = c(DM,'empty payload') if payload_len == 0 else c(YL, str(payload_len)+'B')
            print(f"  {c(GR,'→')}  {lbl2}")
        except:
            print(f"  {c(RD,'✗')}  Invalid {c(DM,f'→ keeping {payload_len}B')}")
    else:
        print(f"  {c(GR,'→')}  keeping {cur_pl_label}")

    # Payload type
    ptype, pat = 5, None
    if payload_len > 0:
        print(f"""
  {c(B+CY,'Payload type')}
  {c(DM,'┌───┬──────────────────────────────────────────────────┐')}
  {c(DM,'│')} {c(GR,'1')} {c(DM,'│')} random bits     {c(DM,'(0 or 1 per byte)')}                {c(DM,'│')}
  {c(DM,'│')} {c(GR,'2')} {c(DM,'│')} random hex      {c(DM,'(0x00–0xFF random bytes)')}         {c(DM,'│')}
  {c(DM,'│')} {c(GR,'3')} {c(DM,'│')} repeat pattern  {c(DM,'(single byte repeated)')}           {c(DM,'│')}
  {c(DM,'│')} {c(GR,'4')} {c(DM,'│')} arithmetic      {c(DM,'(incrementing with ops)')}          {c(DM,'│')}
  {c(DM,'│')} {c(GR,'5')} {c(DM,'│')} mixed           {c(DM,'(printable ASCII + symbols)')}      {c(DM,'│')}
  {c(DM,'│')} {c(GR,'6')} {c(DM,'│')} bit stream      {c(DM,'(random runs of 0s and 1s)')}       {c(DM,'│')}
  {c(DM,'│')} {c(GR,'7')} {c(DM,'│')} hex pair        {c(DM,'(two-byte alternating pattern)')}   {c(DM,'│')}
  {c(DM,'│')} {c(GR,'8')} {c(DM,'│')} custom hex      {c(DM,'(you supply the bytes)')}           {c(DM,'│')}
  {c(DM,'└───┴──────────────────────────────────────────────────┘')}""")
        try:    ptype = int(input(f"  {c(WH,'→')} [5]: ").strip() or 5); ptype = ptype if 1<=ptype<=8 else 5
        except: ptype = 5
        if ptype == 3:
            try:    pat = int((input(f"  {c(CY,'Pattern byte hex')} [AA]: ").strip() or "AA"), 16) & 0xFF
            except: pat = 0xAA
    else:
        print(f"  {c(DM,'→  payload type skipped (empty payload)')}")

    padding = ask_padding()
    count, interval, timeout, wait = ask_send_params()

    print(f"\n  {c(GR,'Sending')} {c(YL,str(count))} packet(s) to {c(BL,dst)} ...\n")
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
        print(f"  {c(DM,f'[{i+1:>4}/{count}]')}"
              f"  {c(BL,src)} {c(DM,'→')} {c(BL,dst)}"
              f"  {c(CY,f'ICMP {itype}/{icode}')}"
              f"  id={c(YL,str(iid))}  seq={c(YL,str(seq))}"
              f"  pay={c(YL,str(len(payload))+'B')}"
              f"  ICMPck={c(MG,f'0x{fck:04x}')}"
              f"  IPck={c(MG,f'0x{ip_ck_f:04x}')}"
              f"  ID={c(MG,f'0x{cur_id:04x}')}")

        if wait:
            if ans:
                r_ip   = ans[0][1][IP]   if IP   in ans[0][1] else None
                r_icmp = ans[0][1][ICMP] if ICMP in ans[0][1] else None
                print(f"       {c(GR,'↳')}  reply from {c(BL, r_ip.src if r_ip else '?')}")
                if r_icmp:
                    recv = bytes(r_icmp.payload) if r_icmp.payload else b''
                    ok   = checksum(bytes(r_icmp)) == 0
                    ck_s = c(GR,'OK') if ok else c(RD,'BAD')
                    mt_s = c(GR,'YES') if recv==payload else c(RD,f'NO  (sent {len(payload)}B  recv {len(recv)}B)')
                    print(f"          ck={ck_s}  match={mt_s}")
            else:
                print(f"       {c(YL,'↳')}  no reply {c(DM,'(timeout)')}")

        cur_id = (cur_id + 1) % 65536
        if i < count-1: time.sleep(interval)

    print(f"\n  {c(GR+B,'Done.')}")

if __name__ == "__main__":
    try:    main()
    except KeyboardInterrupt: print(f"\n\n  {c(YL,'Stopped.')}")
    except Exception as e:    print(f"\n  {c(RD,'Error:')} {e}")
