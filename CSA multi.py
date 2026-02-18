import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SurgicalGatekeeper:
    def __init__(self, iface):
        self.iface = iface
        self.target_mac = None
        self.setup_monitor()
        
        self.root = tk.Tk()
        self.root.title("WPA3 State Auditor")
        self.root.geometry("600x400")
        self.root.configure(bg="#050505")

        self.status = tk.Label(self.root, text="WAITING FOR SAE HANDSHAKE...", fg="#00FF41", bg="#050505", font=("Courier", 12))
        self.status.pack(pady=50)

        threading.Thread(target=self.sniff_logic, daemon=True).start()

    def setup_monitor(self):
        # Using your hardware lock logic
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo iw dev {self.iface} set type monitor")

    def sniff_logic(self):
        def check_handshake(pkt):
            # Logic: Look for Authentication frames (Type 0, Subtype 11)
            if pkt.haslayer(Dot11Auth):
                # 0x0003 is the SAE (Dragonfly) Algorithm
                if pkt.algo == 3:
                    self.status.config(text=f"DETECTED SAE FROM: {pkt.addr2}\nREADY FOR RELAY AUDIT", fg="yellow")
                    # This is where a researcher would trigger the Relay Drop
        
        sniff(iface=self.iface, prn=check_handshake, store=0)

    def shutdown(self):
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 gatekeeper.py [iface]")
    else: SurgicalGatekeeper(sys.argv[1]).root.mainloop()
