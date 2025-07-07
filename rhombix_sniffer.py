#!/usr/bin/env python3

from scapy.all import (
    sniff, get_if_list, wrpcap, ARP,
    ICMP, DNS, TCP, UDP, Raw, IP
)
from datetime import datetime
import os

# Map GUID → Friendly Names (matched from your PowerShell data)
GUID_NAME_MAP = {
    "3F0F319A-9CF7-45B3-B368-BB82813D1202": "Wifi (Intel Dual Band Wireless‑N 7265)",
    "440C8D1D-9B5E-4CE5-AA68-A38B05A1BF28": "Ethernet/Other Adapter 1",
    "98E9265C-02C1-402A-9361-32F6C9F25E2B": "Ethernet/Other Adapter 2",
    "80C09D02-164A-4086-87FA-40BC86914A8E": "Ethernet/Other Adapter 3",
    "C94F32F4-DB2F-40C9-9600-770F601936D8": "VMware VMnet8",
    "30560932-A61F-4957-86EA-568C70C4DB82": "VMware VMnet1",
    "2A274D2A-A754-46D0-A395-ACD511DB1B54": "Adapter 6",
    "940E330B-2481-41C6-A33C-F5AA7E9D0D54": "Adapter 7",
    "28DA0C88-CB99-4225-8DCE-50C03FD90B69": "Adapter 9"
}

captured_packets = []
packet_count = 0

def list_interfaces_named():
    raw = get_if_list()
    idx_map = {}
    print("📡 Available Interfaces:")
    for i, iface in enumerate(raw):
        name = iface
        for guid, friendly in GUID_NAME_MAP.items():
            if guid.lower() in iface.lower():
                name = friendly
                break
        print(f"{i}: {name}")
        idx_map[i] = iface
    return idx_map

def analyze_packet(packet):
    global packet_count
    packet_count += 1
    ts = datetime.now().strftime('%H:%M:%S')
    captured_packets.append(packet)

    if packet.haslayer(ARP):
        arp = packet[ARP]
        if arp.op == 1:
            print(f"[{ts}] ARP Request: Who has {arp.pdst}? Tell {arp.psrc}")
        elif arp.op == 2:
            print(f"[{ts}] ARP Reply: {arp.psrc} is at {arp.hwsrc}")

    elif packet.haslayer(ICMP):
        ic = packet[ICMP]
        if ic.type == 8:
            print(f"[{ts}] ICMP Echo Request → {packet[IP].dst}")
        elif ic.type == 0:
            print(f"[{ts}] ICMP Echo Reply ← {packet[IP].src}")
        else:
            print(f"[{ts}] ICMP type {ic.type}")

    elif packet.haslayer(DNS) and packet.haslayer(UDP):
        dns = packet[DNS]
        if dns.qr == 0:
            print(f"[{ts}] DNS Query → {dns.qd.qname.decode(errors='ignore')}")

    elif packet.haslayer(TCP):
        t = packet[TCP]; src, dst = packet[IP].src, packet[IP].dst
        s, d = t.sport, t.dport
        flags = t.flags
        flag_str = f"SYN={bool(flags & 0x02)} ACK={bool(flags & 0x10)} FIN={bool(flags & 0x01)}"
        print(f"[{ts}] TCP {src}:{s} → {dst}:{d} | {flag_str}")
        if d == 80 and packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors='ignore')
            if payload.startswith("GET") or payload.startswith("POST"):
                print(f"    HTTP {payload.splitlines()[0]}")

    elif packet.haslayer(UDP):
        u = packet[UDP]
        print(f"[{ts}] UDP {packet[IP].src}:{u.sport} → {packet[IP].dst}:{u.dport}")

    else:
        print(f"[{ts}] Other: {packet.summary()}")

def save_pcap():
    if not captured_packets:
        print("⚠️ No packets captured.")
        return
    fname = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    wrpcap(fname, captured_packets)
    print(f"\n✅ Saved {len(captured_packets)} packets to {os.path.abspath(fname)}")

def start_sniff(iface):
    print(f"\n🔍 Sniffing on: {iface}")
    print("Press Ctrl+C to stop...\n")
    try:
        sniff(iface=iface, prn=analyze_packet, store=True)
    except KeyboardInterrupt:
        print("\n⏹️ Capture stopped.")
    finally:
        save_pcap()

if __name__ == "__main__":
    idx_map = list_interfaces_named()
    sel = int(input("Select interface number: "))
    start_sniff(idx_map.get(sel))
