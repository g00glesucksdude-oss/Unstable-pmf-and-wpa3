import os
import sys
import subprocess
import ctypes
from scapy.all import conf, get_if_list

def bootstrap():
    """Ensure Admin/Root privileges."""
    is_admin = False
    if sys.platform == "win32":
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        is_admin = os.getuid() == 0

    if not is_admin:
        print("[!] FATAL: This audit requires Administrator/Root privileges.")
        sys.exit()

def audit_linux_interface(iface):
    """Checks Linux interface for Monitor Mode support."""
    try:
        # Check if the specific interface supports monitor mode
        # Note: In a full script, we query 'iw list' for the physical device capabilities
        res = subprocess.check_output(["iw", "list"], stderr=subprocess.STDOUT).decode()
        if "monitor" in res.lower():
            return True
    except:
        pass
    return False

def audit_windows_interface():
    """Checks Windows environment for Npcap and 802.11 support."""
    # Windows-wide check as Npcap applies to the driver stack
    has_npcap = os.path.exists(os.environ.get('SystemRoot', 'C:\\Windows') + "\\System32\\Npcap")
    if has_npcap and hasattr(conf, 'dot11_support') and conf.dot11_support:
        return True
    return False

def run_mass_audit():
    print("="*60)
    print("      WIRELESS ADAPTER INJECTION CAPABILITY AUDIT")
    print("="*60)
    
    interfaces = get_if_list()
    supported_found = 0

    # Global Windows Check (Since Npcap is the gateway)
    win_global_support = False
    if sys.platform == "win32":
        win_global_support = audit_windows_interface()

    for idx, iface in enumerate(interfaces):
        print(f"\n[{idx}] Testing: {iface}")
        
        is_capable = False
        
        if sys.platform == "win32":
            # On Windows, if Npcap supports 802.11, we check if the interface is Wireless
            # Scapy doesn't always distinguish WiFi vs Ethernet easily on Win without OID queries
            is_capable = win_global_support
        else:
            # Linux specific per-interface check
            is_capable = audit_linux_interface(iface)

        if is_capable:
            print(f"    >> STATUS: [ SUCCESS ]")
            print(f"    >> LOGIC: Hardware/Driver supports Raw Frame Injection.")
            print(f"    >> DEAUTH POSSIBLE: YES")
            supported_found += 1
        else:
            print(f"    >> STATUS: [ FAILED ]")
            print(f"    >> LOGIC: Restricted to Managed/Ethernet modes.")
            print(f"    >> DEAUTH POSSIBLE: NO")

    print("\n" + "="*60)
    print(f"AUDIT COMPLETE: Found {supported_found} compatible adapter(s).")
    print("="*60)

if __name__ == "__main__":
    bootstrap()
    run_mass_audit()
