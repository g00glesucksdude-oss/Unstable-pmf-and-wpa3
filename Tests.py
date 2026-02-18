import os, sys, time, threading, subprocess
from scapy.all import *
import tkinter as tk

class HotspotAutoAuditor:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {} # {Client: {"BSSID": bssid, "RSSI": rssi, "CH": ch}}
        self.running = True
        self.scanning = True
        
        self.setup_hardware()
        
        self.root = tk.Tk()
        self.root.title("Hotspot Logic Auditor v2.0")
        self.root.geometry("900x700")
        self.root.configure(bg="#0a0a0a")

        # UI Components
        self.label = tk.Label(self.root, text="Select a Client to Audit", fg="#00FF41", bg="#0a0a0a", font=("Courier", 12))
        self.label.pack(pady=5)

        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", font=("Courier", 10), height=20)
        self.listbox.pack(padx=10, pady=10, fill="both", expand=True)

        btn_frame = tk.Frame(self.root, bg="#0a0a0a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="RUN AUDIT", command=self.prepare_audit, bg="#880000", fg="white", width=20).pack(side="left", padx=10)
        tk.Button(btn_frame, text="EXIT & REPAIR", command=self.shutdown, bg="#444", fg="white", width=20).pack(side="left", padx=10)

        self.console = tk.Text(self.root, bg="#000", fg="#00FF41", height=10, font=("Courier", 9))
        self.console.pack(padx=10, pady=10, fill="x")

        # Start background threads
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner_loop, daemon=True).start()

    def log(self, msg):
        self.console.insert(tk.END, f"> {msg}\n")
        self.console.see(tk.END)

    def setup_hardware(self):
        os.system("sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def hopper(self):
        ch = 1
        while self.scanning:
            os.system(f"sudo iw dev {self.iface} set channel {ch}")
            self.current_ch = ch
            ch = (ch % 13) + 1
            time.sleep(0.5)

    def scanner_loop(self):
        def callback(pkt):
            if self.scanning and pkt.haslayer(Dot11):
                dot11 = pkt.getlayer(Dot11)
                # Logic: We want Clients (addr2) communicating with BSSIDs (addr3)
                if dot11.addr2 and dot11.addr3 and dot11.addr2 != dot11.addr3:
                    client, bssid = dot11.addr2, dot11.addr3
                    if client not in self.discovered and client != "ff:ff:ff:ff:ff:ff":
                        rssi = getattr(pkt, 'dBm_AntSignal', -100)
                        self.discovered[client] = {"BSSID": bssid, "CH": self.current_ch, "RSSI": rssi}
                        self.root.after(0, self.update_listbox)
        sniff(iface=self.iface, prn=callback, store=0)

    def update_listbox(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.discovered.items():
            self.listbox.insert(tk.END, f"Client: {mac} | Hotspot: {info['BSSID']} | CH: {info['CH']} ({info['RSSI']}dBm)")

    def prepare_audit(self):
        selection = self.listbox.curselection()
        if not selection: return
        
        client_mac = list(self.discovered.keys())[selection[0]]
        target_info = self.discovered[client_mac]
        
        self.scanning = False # Stop hopper
        self.log(f"AUDIT START: Targeting {client_mac} on Channel {target_info['CH']}")
        
        # Lock channel and run the logic check
        os.system(f"sudo iw dev {self.iface} set channel {target_info['CH']}")
        threading.Thread(target=self.run_logic_checks, args=(client_mac, target_info['BSSID']), daemon=True).start()

    def run_logic_checks(self, client, bssid):
        self.log("--- Step 1: Hardware Injection Check ---")
        test_pkt = RadioTap()/Dot11(addr1=bssid, addr2=client, addr3=bssid)/Dot11Auth(algo=0, seqnum=1, status=0)
        try:
            sendp(test_pkt, iface=self.iface, count=1, verbose=False)
            self.log("[+] Hardware injection: SUCCESS")
        except:
            self.log("[-] Hardware injection: FAILED")

        self.log("--- Step 2: Protocol Support Check ---")
        # Logic: Sniff for a beacon from this BSSID to check for WPA3/OCV
        self.log("[*] Probing AP Information Elements...")
        sniff(iface=self.iface, timeout=5, prn=lambda p: self.check_rsn(p, bssid))

    def check_rsn(self, pkt, bssid):
        if pkt.haslayer(Dot11Beacon) and pkt.addr3 == bssid:
            rsn = pkt.getlayer(Dot11EltRSN)
            if rsn:
                info = rsn.info.hex()
                if "000fac08" in info and "000fac02" in info:
                    self.log("[!] TRANSITION MODE detected (Weak)")
                elif "000fac08" in info:
                    self.log("[+] PURE WPA3 detected")
                else:
                    self.log("[+] LEGACY WPA2 detected")

    def shutdown(self):
        self.scanning = False
        self.running = False
        self.log("Cleaning up and repairing internet...")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type managed")
        os.system(f"sudo ip link set {self.iface} up")
        os.system("sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 auditor.py [interface]")
    else: HotspotAutoAuditor(sys.argv[1]).root.mainloop()
