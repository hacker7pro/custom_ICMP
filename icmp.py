#!/usr/bin/env python3
"""Custom ICMP / Raw Packet Crafter — compact refactor"""

import random, string, time
import scapy.all as scapy
from scapy.utils import checksum
from scapy.all import IP, ICMP, Raw
from scapy.layers.l2 import Ether

DEFAULT_PAYLOAD_LEN = 500

# ── helpers ───────────────────────────────────────────────────────────────────

def src_ip():
    try:    return scapy.get_if_addr(scapy.conf.iface)
    except: return "127.0.0.1"

def prompt(name, bits, def_hex, def_bin, def_dec, lo=None, hi=None, note=None):
    lo_s = f" (min h={hex(lo)[2:].zfill(bits//4)} d={lo})" if lo is not None else ""
    hi_s = f" (max h={hex(hi)[2:].zfill(bits//4)} d={hi})" if hi is not None else ""
    nt_s = f" ({note})" if note else ""
    return input(f"{name} ({bits}b) [h={def_hex}|b={def_bin}|d={def_dec}]{lo_s}{hi_s}{nt_s}\n→ ").strip()

def parse_num(s, default, name, lo=None, hi=None):
    if not s: return default
    s = s.strip().replace(" ", "").lower()
    for base in (10, 16, 2):
        try:
            v = int(s.replace("0x",""), base) if base==16 else int(s, base)
            if (lo is not None and v < lo) or (hi is not None and v > hi):
                print(f"  Note: {name}={v} outside range → using anyway")
            return v
        except ValueError:
            pass
    print(f"  Invalid {name} → using {default}"); return default

def ip_chksum(ver, ihl, tos, tlen, id_, ff, ttl, proto, src, dst, opts=b''):
    h = bytearray()
    h += bytes([(ver<<4)|ihl, tos])
    h += tlen.to_bytes(2,'big') + id_.to_bytes(2,'big') + ff.to_bytes(2,'big')
    h += bytes([ttl, proto, 0, 0]) + src + dst + opts
    s = 0
    for i in range(0, len(h), 2):
        w = (h[i]<<8) + (h[i+1] if i+1<len(h) else 0)
        s = (s+w & 0xffff) + ((s+w) >> 16)
    return ~s & 0xffff

def build_ip_hdr(ver, ihl, tos, tlen, id_, ff, ttl, proto, src, dst, opts, ck):
    h = bytearray([(ver<<4)|ihl, tos])
    h += tlen.to_bytes(2,'big') + id_.to_bytes(2,'big') + ff.to_bytes(2,'big')
    h += bytes([ttl, proto, (ck>>8)&0xff, ck&0xff])
    h += src + dst + opts
    return bytes(h)

def resolve_mac(dst, src):
    lmac = scapy.get_if_hwaddr(scapy.conf.iface)
    _, _, nh = scapy.conf.route.route(dst)
    ip = dst if nh in ("0.0.0.0", src) else nh
    print(f"  Resolving MAC for {ip} ...")
    try:
        mac = scapy.getmacbyip(ip)
        if mac: print(f"  MAC: {mac}"); return lmac, mac
    except Exception as e: print(f"  MAC error: {e}")
    print("  → fallback broadcast"); return lmac, "ff:ff:ff:ff:ff:ff"

def send_frame(ip_bytes, lmac, rmac, timeout):
    pkt = Ether(src=lmac, dst=rmac, type=0x0800) / Raw(load=ip_bytes)
    return scapy.srp(pkt, timeout=timeout, verbose=0, iface=scapy.conf.iface)

def ask_padding():
    if input("\nAdd padding? (y/n) [n]: ").strip().lower() not in ('y','yes'): return b''
    cnt = max(1, min(100, int(input("Count [4]: ") or 4)))
    b   = int((input("Byte hex [00]: ").strip() or "00"), 16) & 0xFF
    print(f"  → {cnt}×0x{b:02x}"); return bytes([b])*cnt

def ask_send_params():
    return (int(input("\nPackets [1]: ") or 1),
            float(input("Interval s [1]: ") or 1),
            float(input("Timeout s [2]: ") or 2))

def hex_to_bytes(s):
    clean = s.replace(" ","").replace("0x","")
    if not clean or not all(c in "0123456789abcdefABCDEF" for c in clean):
        return None
    try:    return bytes.fromhex(clean)
    except: return None

# ── payload generator ─────────────────────────────────────────────────────────

def gen_payload(n, ptype, pat=None):
    if n <= 0: return b''
    if ptype == 1: return bytes(random.randint(0,1) for _ in range(n))
    if ptype == 2: return bytes(random.randint(0,255) for _ in range(n))
    if ptype == 3:
        b = pat if isinstance(pat,int) else random.randint(0,255)
        print(f"  → repeat 0x{b:02x}"); return bytes([b])*n
    if ptype == 4:
        buf, v = bytearray(), 0
        for _ in range(n):
            buf.append(v%256)
            op = random.choice(['+2','*2','/2','nop'])
            if op=='+2': v+=2
            elif op=='*2': v*=2
            elif op=='/2' and v: v//=2
        return bytes(buf)
    if ptype == 5:
        pool = (string.ascii_letters+string.digits+string.punctuation).encode()
        return bytes(random.choice(pool) for _ in range(n))
    if ptype == 6:
        bs = ''.join(random.choice('01') for _ in range(n*8))
        for _ in range(random.randint(2,6)):
            p=random.randint(0,n*8-100); rl=random.randint(16,80)
            bs=bs[:p]+random.choice('01')*rl+bs[p+rl:]
        bs=bs[:n*8]
        buf=bytearray(int(bs[j:j+8].ljust(8,'0'),2) for j in range(0,len(bs),8))
        print("  → bit stream"); return bytes(buf)
    if ptype == 7:
        p = random.choice([(0x55,0xAA),(0xA5,0x5A),(0xFF,0x00),(0xF0,0x0F),(0xCC,0x33),(0xAB,0xCD)])
        print(f"  → hex-pair {p[0]:02X}{p[1]:02X}")
        return bytes(p[j%2] for j in range(n))
    if ptype == 8:
        b = hex_to_bytes(input("Custom hex: ").strip())
        if not b: print("  → invalid → random"); return bytes(random.randint(0,255) for _ in range(n))
        b = b[:n] if len(b)>=n else (b*((n+len(b)-1)//len(b)))[:n]
        print(f"  → custom {len(b)}B"); return b
    return b''

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    print("=== ICMP/Raw Packet Crafter ===")
    print("  Bit/Byte/Hex reference: 4bit=<1B(nibble)=1hex  8bit=1B=2hex  16bit=2B=4hex  32bit=4B=8hex")
    print("─" * 60)
    print("── IP Header ──")

    version = parse_num(prompt("Version",4,"4","0100","4",lo=4,hi=4),          4,  "Version")
    ihl     = parse_num(prompt("IHL",4,"5","0101","5",note="5=20B 6=24B 7=28B"),5,  "IHL")
    dscp    = parse_num(prompt("DSCP",6,"00","000000","0",lo=0,hi=63),          0,  "DSCP")
    ecn     = parse_num(prompt("ECN",2,"00","00","0",lo=0,hi=3),                0,  "ECN")
    ttl     = parse_num(prompt("TTL",8,"40","01000000","64",lo=1,hi=255,note="1B"),64,"TTL")
    proto   = parse_num(prompt("Proto",8,"01","00000001","1",lo=0,hi=255,note="1B"),1,"Proto")
    ip_id   = parse_num(prompt("ID",16,"0000","0"*16,"0",lo=0,hi=65535,note="2B"),0,"ID")
    src     = input(f"Src IP [{src_ip()}]: ").strip() or src_ip()
    dst     = input("Dst IP [8.8.8.8]: ").strip() or "8.8.8.8"

    # IP options
    ip_opts = b''
    if input("\nAdd IP options? (y/n) [n]: ").strip().lower() in ('y','yes'):
        h = input("Options hex — must be multiple of 4 bytes (4B=8 hex chars, 8B=16, 12B=24 ... max 40B=80 hex chars): ").strip().replace(" ","").replace("0x","").upper()
        if h and all(c in "0123456789ABCDEF" for c in h) and len(h)//2 <= 40:
            try:
                ip_opts = bytes.fromhex(h)
                pad = (4-len(ip_opts)%4)%4
                if pad: ip_opts += b'\x00'*pad; print(f"  → padded: {ip_opts.hex().upper()}")
                else:   print(f"  → accepted: {h}")
                ihl = 5 + len(ip_opts)//4
                print(f"  → IHL={ihl} ({ihl*4}B)")
            except Exception as e: print(f"  → error: {e}")
        else: print("  → invalid/too long → no options")

    SRC, DST, tos, ff = scapy.inet_aton(src), scapy.inet_aton(dst), (dscp<<2)|ecn, 0x0000

    # First payload size ask — used for IP checksum preview
    payload_len = max(8, int(input(f"\nICMP Payload size B [already set {DEFAULT_PAYLOAD_LEN} bytes]: ").strip() or DEFAULT_PAYLOAD_LEN))
    print(f"  → payload set to {payload_len}B (can override again inside ICMP header section)")

    # IP checksum
    preview = ip_chksum(version,ihl,tos,ihl*4+8+payload_len,ip_id,ff,ttl,proto,SRC,DST,ip_opts)
    print(f"\n── IP Checksum ──  calc=0x{preview:04x}  ID=0x{ip_id:04x}  opts={ip_opts.hex().upper() or 'none'}")
    cs_in = input(f"Desired IP checksum [0x{preview:04x}]: ").strip()
    ip_custom = bool(cs_in)
    if ip_custom:
        try:    ip_ck = int(cs_in.replace("0x",""),16)&0xFFFF; print(f"  → custom 0x{ip_ck:04x}")
        except: print("  → invalid → auto"); ip_custom = False; ip_ck = preview
    else:
        try:
            nc = max(0,min(len(ip_opts),int(input(f"Options bytes for checksum [0-{len(ip_opts)}] [{len(ip_opts)}]: ").strip() or len(ip_opts))))
            ip_ck = ip_chksum(version,ihl,tos,ihl*4+8+payload_len,ip_id,ff,ttl,proto,SRC,DST,ip_opts[:nc])
            print(f"  → using {nc}B opts → 0x{ip_ck:04x}")
        except: ip_ck = preview

    # Protocol
    print("\n── Protocol ──\n  1. ICMP\n  2. Raw hex")
    use_raw = (input("→ [1]: ").strip() or "1") == "2"

    # ── RAW MODE ─────────────────────────────────────────────────────────────
    if use_raw:
        print("\nAny case accepted (deadBEEF / DEADBEEF / deadbeef)")
        raw_in   = input("Raw hex → ").strip()
        raw_bytes = hex_to_bytes(raw_in)
        if raw_bytes is None:
            print("  → invalid → empty"); raw_bytes = b''; raw_in = ""
        else:
            print(f"  → {raw_in}  ({len(raw_bytes)}B)")

        padding = ask_padding()
        count, interval, timeout = ask_send_params()
        print(f"\nSending {count} pkt(s) to {dst} ...\n")
        lmac, rmac = resolve_mac(dst, src)
        body, cur_id = raw_bytes + padding, ip_id

        for i in range(count):
            tlen = ihl*4 + len(body)
            ck   = ip_ck if ip_custom else ip_chksum(version,ihl,tos,tlen,cur_id,ff,ttl,proto,SRC,DST,ip_opts)
            send_frame(build_ip_hdr(version,ihl,tos,tlen,cur_id,ff,ttl,proto,SRC,DST,ip_opts,ck)+body, lmac, rmac, timeout)
            print(f"  [{i+1}/{count}] RAW  {len(raw_bytes)}B  IP ck=0x{ck:04x}  ID=0x{cur_id:04x}  hex={raw_in}")
            cur_id = (cur_id+1)%65536
            if i < count-1: time.sleep(interval)
        print("\nDone."); return

    # ── ICMP MODE ─────────────────────────────────────────────────────────────
    print("\n── ICMP Layer ──\n  8/0=EchoReq  0/0=EchoRep  3/x=Unreach  11/0=TimeExc\n")
    itype = parse_num(prompt("Type",8,"08","00001000","8",lo=0,hi=255,note="1B"),8,"Type")
    icode = parse_num(prompt("Code",8,"00","00000000","0",lo=0,hi=255,note="1B"),0,"Code")
    iid   = parse_num(prompt("ID",16,"0001","0"*15+"1","1",lo=0,hi=65535,note="2B"),1,"ID")
    seqb  = parse_num(prompt("Seq",16,"0001","0"*15+"1","1",lo=0,hi=65535,note="2B"),1,"Seq")

    ick_in = input("ICMP checksum [auto]: ").strip()
    icmp_custom, icmp_ck_val, icmp_extra = bool(ick_in), None, 0
    if icmp_custom:
        try:   icmp_ck_val = int(ick_in.replace("0x",""),16)&0xFFFF; print(f"  → custom 0x{icmp_ck_val:04x}")
        except: print("  → invalid → auto"); icmp_custom = False
    else:
        if input("Extra bytes in ICMP checksum? (y/n) [n]: ").strip().lower() in ('y','yes'):
            try: icmp_extra = max(0,min(100,int(input("Extra count [0]: ") or 0)))
            except: pass
        print(f"  → auto{f' +{icmp_extra}B' if icmp_extra else ''}")

    pl_override = input(f"\nICMP Payload size B [currently {payload_len}B — press Enter to keep]: ").strip()
    if pl_override:
        new_pl = max(8, int(pl_override))
        print(f"  → overriding {payload_len}B → {new_pl}B"); payload_len = new_pl
    else:
        print(f"  → keeping {payload_len}B")
    print("\nPayload: 1=rand-bits 2=rand-hex 3=repeat 4=arith 5=mixed 6=bits 7=hex-pair 8=custom")
    try:    ptype = int(input("→ [5]: ").strip() or 5); ptype = ptype if 1<=ptype<=8 else 5
    except: ptype = 5
    pat = None
    if ptype == 3:
        try:    pat = int((input("Pattern byte [AA]: ").strip() or "AA"),16)&0xFF
        except: pat = 0xAA

    padding = ask_padding()
    count, interval, timeout = ask_send_params()
    print(f"\nSending {count} pkt(s) to {dst} ...\n")
    lmac, rmac, cur_id = *resolve_mac(dst, src), ip_id

    for i in range(count):
        seq     = (seqb+i)%65536
        payload = gen_payload(payload_len, ptype, pat)
        if not icmp_custom and icmp_extra: payload += b'\x00'*icmp_extra

        ih      = bytes(ICMP(type=itype, code=icode, id=iid, seq=seq))
        auto_ck = checksum(ih[:2]+b'\x00\x00'+ih[4:]+payload)
        fck     = icmp_ck_val if icmp_custom else auto_ck
        icmp_bytes = ih[:2]+fck.to_bytes(2,'big')+ih[4:]+payload+padding

        tlen = ihl*4 + len(icmp_bytes)
        ip_ck_f = ip_ck if ip_custom else ip_chksum(version,ihl,tos,tlen,cur_id,ff,ttl,proto,SRC,DST,ip_opts)
        hdr = build_ip_hdr(version,ihl,tos,tlen,cur_id,ff,ttl,proto,SRC,DST,ip_opts,ip_ck_f)

        ans, _ = send_frame(hdr+icmp_bytes, lmac, rmac, timeout)
        print(f"  [{i+1}/{count}] {src}→{dst}  ICMP {itype}/{icode}  id={iid} seq={seq}  "
              f"pay={len(payload)}B  ICMPck=0x{fck:04x}  IPck=0x{ip_ck_f:04x}  ID=0x{cur_id:04x}")

        if ans:
            r_ip   = ans[0][1][IP]   if IP   in ans[0][1] else None
            r_icmp = ans[0][1][ICMP] if ICMP in ans[0][1] else None
            print(f"  → Reply from {r_ip.src if r_ip else '?'}")
            if r_icmp:
                recv = bytes(r_icmp.payload) if r_icmp.payload else b''
                ok   = checksum(bytes(r_icmp)) == 0
                print(f"    ck={'OK' if ok else 'BAD'}  match={'YES' if recv==payload else f'NO (s={len(payload)} r={len(recv)})'}")
        else:
            print("  → No reply")

        cur_id = (cur_id+1)%65536
        if i < count-1: time.sleep(interval)

    print("\nDone.")

if __name__ == "__main__":
    try:    main()
    except KeyboardInterrupt: print("\nStopped.")
    except Exception as e:    print(f"Error: {e}")
