#!/usr/bin/env python3
"""
Custom ICMP Packet Crafter – IP checksum prompt after IP options
- IP Layer: IHL → options → IP checksum prompt
- IP options update IHL automatically
- ICMP checksum stays in ICMP Layer
- Enhanced prompts with min/max + bytes note

1 Nibble = 4 bits
1 Byte   = 8 bits
1 Byte   = 2 Hex digits
"""

import scapy.all as scapy
from scapy.utils import checksum
from scapy.all import IP, ICMP, Raw
import time
import sys
import random
import string

DEFAULT_PAYLOAD_LEN = 500

def get_default_src_ip():
    try:
        return scapy.get_if_addr(scapy.conf.iface)
    except:
        return "127.0.0.1"

def prompt_field(name, bits, def_hex, def_bin, def_dec, min_val=0, max_val=None, bytes_note=None):
    min_str = f" (min hex={hex(min_val)[2:].zfill(bits//4)}, bin={'0'*bits}, dec={min_val})" if min_val > 0 else ""
    max_str = f" (max hex={hex(max_val)[2:].zfill(bits//4)}, bin={'1'*bits}, dec={max_val})" if max_val else ""
    bytes_str = f" ({bytes_note})" if bytes_note else ""
    msg = f"{name} ({bits} bits)  [default: hex={def_hex} | bin={def_bin} | dec={def_dec}]{min_str}{max_str}{bytes_str}\n→ "
    return input(msg).strip()

def parse_numeric(s, bits, default, field_name, min_val=0, max_val=None):
    if not s: return default
    s = s.replace(" ", "").lower()
    try: val = int(s)
    except: pass
    try:
        if s.startswith("0x"): val = int(s[2:], 16)
        else: val = int(s, 16)
    except: pass
    try: val = int(s, 2)
    except:
        print(f"Invalid {field_name} → using {default}")
        return default
    if min_val <= val <= max_val:
        return val
    print(f"Value out of range for {field_name} (min {min_val}, max {max_val}) → using {default}")
    return default

def print_icmp_reference():
    print("\nCommon ICMP:")
    print("  8/0 → Echo Request")
    print("  0/0 → Echo Reply")
    print("  3/0–15 → Dest Unreachable")
    print("  11/0 → Time Exceeded\n")

def generate_payload(length, ptype_num, pattern_arg=None):
    if length <= 0:
        return b''

    if ptype_num == 1:   # random-bits
        return bytes(random.randint(0, 1) for _ in range(length))

    elif ptype_num == 2: # random-hex
        return bytes(random.randint(0, 255) for _ in range(length))

    elif ptype_num == 3: # repeat-pattern
        b = pattern_arg if isinstance(pattern_arg, int) else random.randint(0, 255)
        print(f"  → Repeat-pattern: 0x{b:02x} repeating")
        return bytes([b]) * length

    elif ptype_num == 4: # arithmetic
        payload = bytearray()
        val = 0
        for _ in range(length):
            payload.append(val % 256)
            op = random.choice(['+2', '*2', '/2', 'nop'])
            if op == '+2': val += 2
            elif op == '*2': val *= 2
            elif op == '/2' and val: val //= 2
        return bytes(payload)

    elif ptype_num == 5: # mixed
        pool = (string.ascii_letters + string.digits + string.punctuation).encode()
        return bytes(random.choice(pool) for _ in range(length))

    elif ptype_num == 6: # raw varied 0/1 bit stream
        bit_string = ''.join(random.choice('01') for _ in range(length * 8))
        for _ in range(random.randint(2, 6)):
            pos = random.randint(0, length * 8 - 100)
            run_len = random.randint(16, 80)
            run_bit = random.choice('01')
            run = run_bit * run_len
            bit_string = bit_string[:pos] + run + bit_string[pos + run_len:]
        bit_string = bit_string[:length * 8]
        payload = bytearray()
        for j in range(0, len(bit_string), 8):
            byte_bits = bit_string[j:j+8]
            if len(byte_bits) < 8:
                byte_bits += '0' * (8 - len(byte_bits))
            byte_val = int(byte_bits, 2)
            payload.append(byte_val)
        print(f"  → Raw bit stream (varied 0/1 sequences)")
        return bytes(payload)

    elif ptype_num == 7: # hex-pattern
        hex_pairs = [
            (0x55, 0xAA), (0xA5, 0x5A), (0xFF, 0x00), (0xF0, 0x0F),
            (0xCC, 0x33), (0xAA, 0x55), (0xAB, 0xCD), (0x12, 0x34)
        ]
        pair = random.choice(hex_pairs)
        print(f"  → Hex-pattern: repeating {hex(pair[0])[2:].upper()} {hex(pair[1])[2:].upper()}")
        payload = bytearray()
        for j in range(length):
            payload.append(pair[j % 2])
        return bytes(payload)

    elif ptype_num == 8: # custom hex payload
        hex_input = input("Enter custom payload as hex string (e.g. deadbeef112233 or 414243): ").strip()
        if not hex_input:
            print("  → No hex input → falling back to random bytes")
            return bytes(random.randint(0, 255) for _ in range(length))

        hex_input = hex_input.replace(" ", "").replace("0x", "").lower()
        if not all(c in '0123456789abcdef' for c in hex_input):
            print("  → Invalid hex → falling back to random bytes")
            return bytes(random.randint(0, 255) for _ in range(length))

        try:
            custom_bytes = bytes.fromhex(hex_input)
        except:
            print("  → Hex conversion failed → falling back to random")
            return bytes(random.randint(0, 255) for _ in range(length))

        if len(custom_bytes) == 0:
            return b''
        if len(custom_bytes) >= length:
            custom_bytes = custom_bytes[:length]
        else:
            repeats = (length + len(custom_bytes) - 1) // len(custom_bytes)
            custom_bytes = (custom_bytes * repeats)[:length]

        print(f"  → Custom hex payload used ({len(custom_bytes)} bytes)")
        return custom_bytes

    return b''

def ask_padding():
    ans = input("\nAdd padding IP→ICMP? (y/n): ").strip().lower()
    if ans not in ['y','yes']: return None
    cnt = int(input("Count (default 4): ") or 4)
    cnt = max(1, min(100, cnt))
    val = input("Byte hex (default 00): ").strip() or "00"
    b = int(val, 16) & 0xFF if len(val) in [1,2] else 0
    print(f"  → {cnt} × 0x{b:02x}")
    return bytes([b]) * cnt

def main():
    print("=== ICMP Crafter – IP & ICMP checksum customization + IP options ===\n")

    # IP Layer
    print("IP Layer:")
    version = parse_numeric(prompt_field("Version",4,"4","0100","4", min_val=4, max_val=4),4,4,"Version")
    ihl     = parse_numeric(prompt_field("IHL",4,"5","0101","5", min_val=5, max_val=15, bytes_note="5-15 words = 20-60 bytes"),4,5,"IHL")
    dscp    = parse_numeric(prompt_field("DSCP",6,"00","000000","0", min_val=0, max_val=63),6,0,"DSCP")
    ecn     = parse_numeric(prompt_field("ECN",2,"00","00","0", min_val=0, max_val=3),2,0,"ECN")
    ttl     = parse_numeric(prompt_field("TTL",8,"40","01000000","64", min_val=1, max_val=255, bytes_note="1 byte"),8,64,"TTL")
    proto   = parse_numeric(prompt_field("Proto",8,"01","00000001","1", min_val=0, max_val=255, bytes_note="1 byte"),8,1,"Proto")
    ip_id   = parse_numeric(prompt_field("ID",16,"0000","0000000000000000","0", min_val=0, max_val=65535, bytes_note="2 bytes"),16,0,"ID")

    src = input(f"Src IP [default {get_default_src_ip()}]: ").strip() or get_default_src_ip()
    dst = input("Dst IP [default 8.8.8.8]: ").strip() or "8.8.8.8"

    # IP Options
    add_options = input("\nAdd IP options? (y/n, default n): ").strip().lower()
    ip_options = None
    if add_options in ['y', 'yes']:
        hex_input = input("Enter IP options as hex string (max 40 bytes = 320 bits, multiple of 4 bytes): ").strip()
        if hex_input:
            hex_input = hex_input.replace(" ", "").replace("0x", "").lower()
            if all(c in '0123456789abcdef' for c in hex_input) and len(hex_input) % 8 == 0 and len(hex_input) // 2 <= 40:
                try:
                    ip_options = bytes.fromhex(hex_input)
                    options_words = len(ip_options) // 4
                    ihl += options_words
                    print(f"  → IP options added ({len(ip_options)} bytes / {len(ip_options)*8} bits, IHL now {ihl} words = {ihl*4} bytes)")
                except:
                    print("  → Invalid hex → no options added")
            else:
                print("  → Invalid hex, not multiple of 4 bytes, or exceeds max 40 bytes → no options added")

    # IP Checksum prompt – after IP options
    ip_chksum_str = input("Desired IP checksum hex (empty = auto): ").strip()
    ip_use_custom = bool(ip_chksum_str)
    ip_desired = None
    ip_extra_bytes = 0
    if ip_use_custom:
        try:
            ip_desired = int(ip_chksum_str.replace("0x",""), 16) & 0xFFFF
            print(f"  → Custom IP checksum: {hex(ip_desired)}")
        except:
            print("  Invalid → auto mode for IP")
            ip_use_custom = False
    else:
        ip_chk_mode = input("IP checksum calculation: default or default + extra bytes? (default/extra): ").strip().lower()
        if ip_chk_mode == 'extra':
            try:
                ip_extra_bytes = int(input("Extra bytes for IP checksum calculation (0-100): ") or 0)
                ip_extra_bytes = max(0, min(100, ip_extra_bytes))
            except:
                ip_extra_bytes = 0
        print(f"  → IP checksum: {'default' if ip_extra_bytes == 0 else f'default + {ip_extra_bytes} extra bytes'}")

    # ICMP Layer
    print("\nICMP Layer:")
    print_icmp_reference()

    itype = parse_numeric(prompt_field("Type",8,"08","00001000","8", min_val=0, max_val=255, bytes_note="1 byte"),8,8,"Type")
    icode = parse_numeric(prompt_field("Code",8,"00","00000000","0", min_val=0, max_val=255, bytes_note="1 byte"),8,0,"Code")
    iid   = parse_numeric(prompt_field("Identifier",16,"0001","0000000000000001","1", min_val=0, max_val=65535, bytes_note="2 bytes"),16,1,"ID")
    seqb  = parse_numeric(prompt_field("Seq base",16,"0001","0000000000000001","1", min_val=0, max_val=65535, bytes_note="2 bytes"),16,1,"Seq")

    icmp_chksum_str = input("Desired ICMP checksum hex (empty = auto): ").strip()
    icmp_use_custom = bool(icmp_chksum_str)
    icmp_desired = None
    icmp_extra_bytes = 0
    if icmp_use_custom:
        try:
            icmp_desired = int(icmp_chksum_str.replace("0x",""), 16) & 0xFFFF
            print(f"  → Custom ICMP checksum: {hex(icmp_desired)}")
        except:
            print("  Invalid → auto mode for ICMP")
            icmp_use_custom = False
    else:
        chk_mode = input("ICMP checksum calculation: default or default + extra bytes? (default/extra): ").strip().lower()
        if chk_mode == 'extra':
            try:
                icmp_extra_bytes = int(input("Extra bytes for ICMP checksum calculation (0-100): ") or 0)
                icmp_extra_bytes = max(0, min(100, icmp_extra_bytes))
            except:
                icmp_extra_bytes = 0
        print(f"  → ICMP checksum: {'default' if icmp_extra_bytes == 0 else f'default + {icmp_extra_bytes} extra bytes'}")

    # Payload type selection (1-8)
    print("\nChoose payload type (enter number 1-8):")
    print("1. random-bits      → only 0 and 1 bytes")
    print("2. random-hex       → random 00–FF bytes")
    print("3. repeat-pattern   → repeating single byte")
    print("4. arithmetic       → math sequence mod 256")
    print("5. mixed            → letters+digits+symbols")
    print("6. bits-pattern     → raw varied 0/1 bit stream (continuous sequences)")
    print("7. hex-pattern      → randomized repeating hex pair per packet")
    print("8. custom hex       → input your own hex string (e.g. deadbeef112233)")
    try:
        ptype = int(input("→ "))
        if not 1 <= ptype <= 8: ptype = 5
    except:
        ptype = 5
        print("Invalid → using 5 (mixed)")

    pattern_byte = None
    if ptype == 3:
        p = input("Pattern byte hex (default AA): ").strip() or "AA"
        try: pattern_byte = int(p, 16) & 0xFF
        except: pattern_byte = 0xAA

    # Length logic
    if ptype == 8:
        payload_len = DEFAULT_PAYLOAD_LEN  # fallback / max size
        print(f"  → Custom hex mode – size will be based on your input (max {DEFAULT_PAYLOAD_LEN} bytes)")
    elif icmp_use_custom:
        parity = input("Preferred payload parity (odd / even): ").strip().lower()
        prefer_odd = parity.startswith('o')
        payload_len = DEFAULT_PAYLOAD_LEN
        print(f"  → Starting {payload_len} bytes – will adjust while keeping {'odd' if prefer_odd else 'even'} parity")
    else:
        try:
            payload_len = int(input(f"Payload size (bytes) [default {DEFAULT_PAYLOAD_LEN}]: ") or DEFAULT_PAYLOAD_LEN)
            payload_len = max(8, payload_len)
        except:
            payload_len = DEFAULT_PAYLOAD_LEN
        print(f"  → Using {payload_len} bytes")

    padding = ask_padding()

    count   = int(input("\nPackets [default 1]: ") or 1)
    interval = float(input("Interval (s) [default 1]: ") or 1)
    timeout  = float(input("Reply timeout (s) [default 2]: ") or 2)

    print(f"\nSending {count} packet(s) to {dst} ...\n")

    for i in range(count):
        seq = (seqb + i) % 65536

        icmp_base = ICMP(type=itype, code=icode, id=iid, seq=seq, chksum=0)

        print(f"  → Generating payload for packet {i+1} (type {ptype})...")
        payload = generate_payload(payload_len, ptype, pattern_byte)

        # Add extra bytes for ICMP checksum if specified
        if not icmp_use_custom and icmp_extra_bytes > 0:
            extra = bytes([0x00] * icmp_extra_bytes)
            payload += extra
            print(f"  → Added {icmp_extra_bytes} extra bytes for ICMP checksum calculation")

        icmp = icmp_base / payload
        icmp_cur_sum = checksum(bytes(icmp))

        icmp_reason = f"auto ({len(payload)} bytes)"
        if icmp_use_custom and icmp_cur_sum != icmp_desired:
            icmp_reason = "custom ICMP checksum → adjusting..."
            found = False
            delta = (icmp_cur_sum - icmp_desired) % 65536
            if len(payload) >= 2:
                current_last = int.from_bytes(payload[-2:], 'big')
                new_last = (current_last - delta) % 65536
                payload = payload[:-2] + new_last.to_bytes(2, 'big')
            else:
                new_append = (0 - delta) % 65536
                payload = payload + new_append.to_bytes(2, 'big')
            if checksum(bytes(icmp_base / payload)) == icmp_desired:
                found = True
                icmp_reason = "matched via last 2 bytes (delta)"
            else:
                for attempt in range(10):
                    delta = (checksum(bytes(icmp_base / payload)) - icmp_desired) % 65536
                    if len(payload) >= 2:
                        current_last = int.from_bytes(payload[-2:], 'big')
                        new_last = (current_last - delta) % 65536
                        payload = payload[:-2] + new_last.to_bytes(2, 'big')
                    else:
                        new_append = (0 - delta) % 65536
                        payload = payload + new_append.to_bytes(2, 'big')
                    if checksum(bytes(icmp_base / payload)) == icmp_desired:
                        found = True
                        icmp_reason = "matched via last 2 bytes (carry fixed)"
                        break

            if not found:
                step = 2
                cl = len(payload)
                for d in range(step, 100, step):
                    for sign in [1, -1]:
                        nl = cl + sign * d
                        if nl < 32: continue
                        if (nl % 2 == 1) == prefer_odd:
                            payload = generate_payload(nl, ptype, pattern_byte)
                            if checksum(bytes(icmp_base / payload)) == icmp_desired:
                                found = True
                                icmp_reason = f"matched after length → {nl} bytes (kept parity)"
                                break
                    if found: break
                if not found:
                    icmp_reason = "could not match exactly – kept original"

        icmp = icmp_base / payload
        icmp.chksum = icmp_desired if icmp_use_custom else icmp_cur_sum

        # IP checksum calculation
        tos = (dscp << 2) | ecn
        ip = IP(version=version, ihl=ihl, tos=tos, ttl=ttl, proto=proto, src=src, dst=dst, id=(ip_id + i)%65536)

        # Add IP options if specified
        if ip_options:
            ip = ip / scapy.Packet(ip_options)

        # Add extra bytes for IP checksum if specified
        ip_payload = payload
        if not ip_use_custom and ip_extra_bytes > 0:
            extra = bytes([0x00] * ip_extra_bytes)
            ip_payload += extra
            print(f"  → Added {ip_extra_bytes} extra bytes for IP checksum calculation")

        ip_tmp = ip / icmp_base / ip_payload  # temporary packet for checksum
        ip_tmp.chksum = 0
        del ip_tmp.chksum  # force recalculation
        ip.chksum = ip_tmp.chksum  # apply calculated value

        pkt = ip
        if padding: pkt /= Raw(padding)
        pkt /= icmp

        print(f"Packet {i+1}/{count}:")
        print(f"  {src} → {dst}   TTL={ttl}   ToS={hex(tos)}")
        print(f"  ICMP {itype}/{icode}   ID={iid}   Seq={seq}")
        print(f"  Payload: {len(payload)} bytes ({'odd' if len(payload)%2 else 'even'})   ICMP Chksum={hex(icmp.chksum)}   IP Chksum={hex(ip.chksum)}")
        print(f"  → {icmp_reason}\n")

        ans, _ = scapy.sr(pkt, timeout=timeout, verbose=0)

        if ans:
            r = ans[0][1]
            print(f"  → Reply from {r.src}")

            r_icmp = r[ICMP]
            r_bytes = bytes(r_icmp)
            chksum_ok = checksum(r_bytes) == 0
            print(f"    Reply checksum: {'VALID' if chksum_ok else 'INVALID'}")

            sent_pl = bytes(pkt[ICMP].payload)
            recv_pl = bytes(r_icmp.payload) if r_icmp.payload else b''
            match = sent_pl == recv_pl
            print(f"    Payload match: {'YES' if match else 'NO'}")
            if not match:
                print(f"      Sent: {len(sent_pl)} B   Recv: {len(recv_pl)} B")
        else:
            print("  → No reply (timeout)")

        if i < count-1:
            time.sleep(interval)

    print("\nDone.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"Error: {e}")
