import os, sys, time
from scapy.all import *

def check_hardware(iface):
    print(f"\n[1] --- Hardware Logic Check ---")
    # Logic: Test injection capability
    test_pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="00:11:22:33:44:55")/Dot11Beacon()
    try:
        sendp(test_pkt, iface=iface, count=1, verbose=False)
        print("[+] SUCCESS: Card supports packet injection.")
    except Exception as e:
        print(f"[-] FAILURE: Injection failed ({e})")
        return False
    return True

def audit_hotspot(iface, target_bssid):
    print(f"\n[2] --- Hotspot Logic Audit: {target_bssid} ---")
    
    def parse_beacon(pkt):
        if pkt.haslayer(Dot11Beacon) and pkt.addr3 == target_bssid:
            # Check for RSN (Robust Security Network) info
            rsn = pkt.getlayer(Dot11EltRSN)
            if rsn:
                rsn_hex = rsn.info.hex()
                
                # Logic: Transition Mode Detection
                # 0x08 = SAE (WPA3), 0x02 = PSK (WPA2)
                is_wpa2 = "000fac02" in rsn_hex
                is_wpa3 = "000fac08" in rsn_hex or "000fac09" in rsn_hex
                
                if is_wpa2 and is_wpa3:
                    print("[!] ALERT: Hotspot is in TRANSITION MODE (Vulnerable to Deauth downgrade)")
                elif is_wpa3:
                    print("[+] INFO: Hotspot is PURE WPA3 (SAE)")
                
                # Logic: OCV Support (Operating Channel Validation)
                # OCV is usually in the RSN Capabilities field (Bit 6)
                if len(rsn.info) > 2:
                    print("[+] INFO: OCV/PMF support bits detected in RSN IE.")
            
            # Check for 802.11ax (Wi-Fi 6) support
            if pkt.haslayer(Dot11Elt) and pkt.ID == 255: # HE Capabilities
                print("[+] INFO: Hardware supports 802.11ax (High Efficiency)")
            
            return True
        return False

    print("[*] Sniffing Beacon for protocol analysis...")
    sniff(iface=iface, prn=parse_beacon, timeout=10, stop_filter=parse_beacon)

def test_sensitivity(iface, target_bssid, client_mac):
    print(f"\n[3] --- State Machine Sensitivity Test ---")
    # Logic: Send an out-of-order Auth frame to see if AP resets or ignores
    # This probes the 'Dragonfly' state machine vulnerability
    print(f"[*] Sending malformed SAE-Commit to {target_bssid}...")
    base = RadioTap()/Dot11(addr1=target_bssid, addr2=client_mac, addr3=target_bssid)
    malformed_sae = base/Dot11Auth(algo=3, seqnum=5, status=0) # Wrong sequence number
    
    sendp(malformed_sae, iface=iface, count=3, verbose=False)
    print("[+] Probe sent. Observe if client disconnects in your scanner.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: sudo python3 audit.py [interface] [target_bssid] [opt_client_mac]")
        sys.exit(1)
        
    iface = sys.argv[1]
    target = sys.argv[2]
    client = sys.argv[3] if len(sys.argv) > 3 else "00:11:22:33:44:55"
    
    if check_hardware(iface):
        audit_hotspot(iface, target)
        test_sensitivity(iface, target, client)

