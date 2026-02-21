import sys
import os
import subprocess
from scapy.all import *

def check_linux_capabilities():
    print("[*] Checking Linux Wireless Capabilities...")
    try:
        # Check if 'iw' is installed
        res = subprocess.check_output(["iw", "list"], stderr=subprocess.STDOUT).decode()
        if "monitor" in res.lower():
            print("[+] SUCCESS: Driver reports Monitor Mode support.")
        else:
            print("[-] FAILURE: Monitor Mode not found in 'iw list'.")
            
        # Check for injection via aireplay-ng if available
        print("[*] Suggestion: Run 'sudo aireplay-ng --test <iface>' for functional verification.")
    except FileNotFoundError:
        print("[-] Error: 'iw' tool not found. Please install wireless-tools/iw.")

def check_windows_capabilities():
    print("[*] Checking Windows Wireless Capabilities...")
    # Windows requires Npcap for raw 802.11
    if not os.path.exists(r"C:\Windows\System32\Npcap"):
        print("[-] FAILURE: Npcap not detected. Windows cannot inject raw frames without Npcap.")
        return

    print("[+] Npcap detected. Testing interface access...")
    # List interfaces via Scapy/Npcap
    try:
        interfaces = get_windows_if_list()
        for i in interfaces:
            print(f"    - Found: {i['name']} ({i['description']})")
    except Exception as e:
        print(f"[-] Error querying interfaces: {e}")

def functional_injection_test(iface):
    """Sends a single Null Function frame to test if hardware accepts raw transmission."""
    print(f"[*] Attempting functional injection test on {iface}...")
    # Null Function Frame: A harmless frame often used for power management
    packet = RadioTap()/Dot11(type=2, subtype=4, addr1="ff:ff:ff:ff:ff:ff", 
                              addr2="00:11:22:33:44:55", addr3="ff:ff:ff:ff:ff:ff")
    try:
        sendp(packet, iface=iface, count=1, verbose=False)
        print("[+!!+] SUCCESS: Packet accepted by the driver for injection.")
    except Exception as e:
        print(f"[-] FAILURE: Injection failed. Error: {e}")

if __name__ == "__main__":
    if not os.getuid == 0 and sys.platform != "win32":
        print("[!] Warning: This script must be run as Root/Admin to access raw sockets.")
    
    if sys.platform == "linux" or sys.platform == "linux2":
        check_linux_capabilities()
    elif sys.platform == "win32":
        check_windows_capabilities()
    
    print("\n--- Manual Test ---")
    iface = input("Enter interface name to test functional injection (or Enter to skip): ")
    if iface:
        functional_injection_test(iface)

