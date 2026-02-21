import subprocess
import sys

def setup_hotspot(ssid, password, interface="wlan0"):
    try:
        print(f"[*] Creating hotspot: {ssid}...")
        
        # 1. Create the hotspot profile
        create_cmd = [
            "sudo", "nmcli", "device", "wifi", "hotspot",
            "ifname", interface,
            "con-name", "KaliHotspot",
            "ssid", ssid,
            "password", password
        ]
        subprocess.run(create_cmd, check=True)
        
        print(f"[+] Hotspot '{ssid}' is now active.")
        print("[!] Note: This may disconnect your current Wi-Fi session.")
        
    except subprocess.CalledProcessError as e:
        print(f"[-] Error creating hotspot: {e}")

if __name__ == "__main__":
    # Run with: sudo python3 script.py
    setup_hotspot("KaliNet", "kali12345")

