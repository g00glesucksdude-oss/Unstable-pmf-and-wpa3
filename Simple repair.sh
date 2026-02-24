#!/bin/bash
# 1. Kill any lingering exploit processes (like airmon-ng or the python scripts)
sudo pkill -f "python3"
sudo pkill -f "airmon-ng"

# 2. Fix the interface mode (Replace 'wlan0' with your card name)
# This forces the card out of Monitor mode back to Managed mode
sudo ip link set wlan0 down
sudo iw wlan0 set type managed
sudo ip link set wlan0 up

# 3. Restart the core networking services that the scripts likely killed
sudo systemctl restart NetworkManager
sudo systemctl restart wpa_supplicant

# 4. Request a fresh IP address from the router
sudo dhclient -v wlan0

echo "Adapter reset to Managed mode. Internet should return in 5-10 seconds."

