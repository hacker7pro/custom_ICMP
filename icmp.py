#!/usr/bin/env python3
"""
Custom ICMP Packet Crafter – 500-byte payload base + response checking
- Short summary instead of full packet.show()
- Verifies response: payload exact match + ICMP checksum validity
"""

import scapy.all as scapy
from scapy.utils import checksum
from scapy.all import IP, ICMP, Raw
import time
import sys
import random
import string

BASE_PAYLOAD_LENGTH = 500

def get_default_src_ip():
    try:
        return scapy.get_if_addr(scapy.conf.iface)
    except:
        return "127.0.0.1"

def prompt_field(name, bits, def_hex, def_bin, def_dec):
    example = f"  (ex: hex={def_hex}, bin={def_bin}, dec={def_dec})"
    msg = f"{name} ({bits} bits)  [default: hex={def_hex} | bin={def_bin} | dec={def_dec}]{example}\n→ "
    return input(msg).strip()

def parse_numeric(s, bits, default, field_name):
    if not s:
        return default
    s_clean = s.replace(" ", "").lower()
    try: return int(s_clean)
    except: pass
    try:
        if s_clean.startswith("0x"):
            return int(s_clean[2:], 16)
        return int(s_clean, 16)
    except: pass
    try: return int(s_clean, 2)
    except:
        print(f"  Invalid {field_name} → default {default}")
        return default

def print_icmp_reference():
    print("\nCommon ICMP:")
    print("  8/0 → Echo Request")
    print("  0/0 → Echo Reply")
    print("  3/0–15 → Dest Unreachable")
    print("  11/0 → Time Exceeded\n")

def generate_payload(length, ptype):
    if length == 0: return b''
    if ptype == 'numeric':   pool = string.digits.encode()
    elif ptype == 'alphabetic': pool = string.ascii_letters.encode()
    else: pool = (string.ascii_letters + string.digits + string.punctuation).encode()
    return bytes(random.choice(pool) for _ in range(length))

def ask_for_padding():
    add = input("\nAdd padding between IP & ICMP? (y/n, default n): ").strip().lower()
    if add not in ['y','yes']: 
        print("  → No padding")
        return None
    try: pad_len = max(1, min(100, int(input("Padding bytes (default 4): ") or 4)))
    except: pad_len = 4
    pad_val = input("Padding byte hex (default 00): ").strip() or "00"
    try: pad_byte = int(pad_val, 16) & 0xFF
    except: pad_byte = 0
    print(f"  → {pad_len} bytes of 0x{pad_byte:02x}")
    return bytes([pad_byte]) * pad_len

def main():
    print("=== ICMP Crafter – 500-byte payload + response check ===\n")

    # IP Layer
    print("IP Layer:")
    version = parse_numeric(prompt_field("Version",4,"4","0100","4"),4,4,"Version")
    ihl     = parse_numeric(prompt_field("IHL",4,"5","0101","5"),4,5,"IHL")
    dscp    = parse_numeric(prompt_field("DSCP",6,"00","000000","0"),6,0,"DSCP")
    ecn     = parse_numeric(prompt_field("ECN",2,"00","00","0"),2,0,"ECN")
    ttl     = parse_numeric(prompt_field("TTL",8,"40","01000000","64"),8,64,"TTL")
    proto   = parse_numeric(prompt_field("Protocol",8,"01","00000001","1"),8,1,"Protocol")
    ip_id   = parse_numeric(prompt_field("ID",16,"0000","0000000000000000","0"),16,0,"ID")

    src = input(f"Source IP [default {get_default_src_ip()}]: ").strip() or get_default_src_ip()
    dst = input("Destination IP [default 8.8.8.8]: ").strip() or "8.8.8.8"

    # ICMP Layer
    print("\nICMP Layer:")
    print_icmp_reference()
    icmp_type  = parse_numeric(prompt_field("Type",8,"08","00001000","8"),8,8,"Type")
    icmp_code  = parse_numeric(prompt_field("Code",8,"00","00000000","0"),8,0,"Code")
    identifier = parse_numeric(prompt_field("Identifier",16,"0001","0000000000000001","1"),16,1,"ID")
    seq_base   = parse_numeric(prompt_field("Sequence base",16,"0001","0000000000000001","1"),16,1,"Seq")

    chksum_in = input("Desired checksum hex (empty = auto): ").strip()
    desired_chksum = None
    if chksum_in:
        try: 
            desired_chksum = int(chksum_in.replace("0x",""), 16) & 0xFFFF
            print(f"  → Custom checksum: {hex(desired_chksum)}")
        except: print("  Invalid → auto")

    # Payload
    ptype = input("\nPayload type (numeric / alphabetic / mixed): ").strip().lower()
    if ptype not in ['numeric','alphabetic','mixed']: ptype = 'mixed'

    parity_choice = input("Preferred parity if length changes (odd/even): ").strip().lower()
    prefer_odd = parity_choice.startswith('o')

    print(f"  → Generating {BASE_PAYLOAD_LENGTH}-byte {ptype} payload...")
    base_payload = generate_payload(BASE_PAYLOAD_LENGTH, ptype)

    inter_padding = ask_for_padding()

    # Sending params
    count   = int(input("\nPackets to send [default 1]: ") or 1)
    interval = float(input("Delay between sends (s) [default 1]: ") or 1)
    timeout  = float(input("Response timeout per packet (s) [default 2]: ") or 2)

    print(f"\nSending {count} packet(s) to {dst} (timeout {timeout}s)...\n")

    for i in range(count):
        seq = (seq_base + i) % 65536

        icmp_base = ICMP(type=icmp_type, code=icmp_code, id=identifier, seq=seq, chksum=0)
        payload = base_payload
        icmp = icmp_base / payload
        current_sum = checksum(bytes(icmp))

        reason = "auto (500 bytes)"
        if desired_chksum is not None and current_sum != desired_chksum:
            reason = "custom checksum attempt"
            found = False
            for adj in range(65536):
                test_pl = payload[:-2] + adj.to_bytes(2, 'big') if len(payload) >= 2 else payload + adj.to_bytes(2, 'big')
                if checksum(bytes(icmp_base / test_pl)) == desired_chksum:
                    payload = test_pl
                    found = True
                    reason = "matched via last 2 bytes"
                    break
            if not found:
                step = 2
                for delta in range(step, 200, step):
                    for sign in [1, -1]:
                        new_len = len(payload) + sign * delta
                        if new_len < 8: continue
                        if (new_len % 2 == 1) == prefer_odd or delta > 20:
                            payload = generate_payload(new_len, ptype)
                            if checksum(bytes(icmp_base / payload)) == desired_chksum:
                                found = True
                                reason = f"matched after length → {new_len} bytes"
                                break
                    if found: break
                if not found:
                    reason = "could not match exactly – kept 500 bytes"

        icmp = icmp_base / payload
        icmp.chksum = desired_chksum if desired_chksum is not None else current_sum

        tos = (dscp << 2) | ecn
        ip = IP(version=version, ihl=ihl, tos=tos, ttl=ttl, proto=proto, src=src, dst=dst, id=(ip_id + i)%65536)

        pkt = ip
        if inter_padding: pkt /= Raw(inter_padding)
        pkt /= icmp

        # Short summary instead of full show()
        print(f"Packet {i+1}/{count} summary:")
        print(f"  Src → Dst: {src} → {dst}")
        print(f"  TTL: {ttl}   ToS: {hex(tos)} (DSCP={dscp}/ECN={ecn})")
        print(f"  ICMP type/code: {icmp_type}/{icmp_code}  ID: {identifier}  Seq: {seq}")
        print(f"  Payload len: {len(payload)} bytes")
        print(f"  Checksum: {hex(icmp.chksum)}")
        if inter_padding:
            print(f"  Padding: {len(inter_padding)} bytes of 0x{inter_padding[0]:02x}")
        print(f"  → {reason}\n")

        # Send + receive
        ans, _ = scapy.sr(pkt, timeout=timeout, verbose=0)

        if ans:
            resp = ans[0][1]
            print(f"  → Reply from {resp.src} (RTT: {ans[0][1].time - ans[0][0].sent_time:.3f}s)")
            
            # Check response ICMP checksum
            resp_icmp_bytes = bytes(resp[ICMP])
            resp_checksum_ok = checksum(resp_icmp_bytes) == 0
            print(f"    Response ICMP checksum: {'VALID' if resp_checksum_ok else 'INVALID'}")

            # Check payload exact match (byte-by-byte / bit-by-bit equivalent)
            sent_pl = bytes(pkt[ICMP].payload)
            recv_pl = bytes(resp[ICMP].payload) if resp.haslayer(ICMP) and resp[ICMP].haslayer(Raw) else b''
            match = sent_pl == recv_pl
            print(f"    Payload exact match: {'YES' if match else 'NO'}")
            if not match:
                print(f"      Sent len: {len(sent_pl)}   Received len: {len(recv_pl)}")
        else:
            print("  → No response (timeout)")

        if i < count - 1:
            time.sleep(interval)

    print("\nFinished.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
