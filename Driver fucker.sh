#!/bin/bash

# LOGIC CHECK: ARE WE ROOT?
if [[ $EUID -ne 0 ]]; then 
   echo "[-] Put your mask on. Run with sudo." 
   exit 1
fi

echo "[+] STARTING DRIVER SURGERY: RTL88x2BU"
echo "[+] Target: 5GHz Unlock + Packet Injection + Anti-Fry"

# --- 1. THE KERNEL LOCKDOWN ---
echo "[+] Pinning kernel to prevent auto-rolling..."
apt-mark hold linux-image-amd64 linux-headers-amd64

# --- 2. THE TRANSPLANT PREP ---
echo "[+] Installing surgical tools (headers & build-essential)..."
apt update
apt install -y build-essential dkms git bc linux-headers-$(uname -r)

# --- 3. EXCISE THE WEAK DRIVER ---
echo "[+] Blacklisting conflicting rtw88 drivers..."
cat <<EOF > /etc/modprobe.d/blacklist-rtw88.conf
blacklist rtw88_8822bu
blacklist rtw88_usb
blacklist rtw88_core
EOF

# --- 4. THE RECONSTRUCTION (MORROWNR DRIVER) ---
if [ ! -d "88x2bu-20210702" ]; then
    git clone https://github.com/morrownr/88x2bu-20210702.git
fi
cd 88x2bu-20210702

echo "[+] Patching Makefile for 5GHz Unrestricted Scanning..."
sed -i 's/CONFIG_RTW_DFS_REGION_CONF = n/CONFIG_RTW_DFS_REGION_CONF = y/' Makefile

echo "[+] Applying Anti-Fry thermal safety (Disabling VHT Turbo)..."
sed -i 's/CONFIG_80211AC_VHT_TURBO = y/CONFIG_80211AC_VHT_TURBO = n/' Makefile

# --- 5. THE INSTALL ---
echo "[+] Compiling... grab a coffee, this takes a few minutes."
./remove-driver.sh
./install-driver.sh

# --- 6. DRIVER TUNING ---
echo "[+] Setting high-power region and USB 2.0 safety mode..."
cat <<EOF > /etc/modprobe.d/88x2bu.conf
# 0=USB2 (Safe/Cool), 1=USB3 (Aggressive/Hot)
options 88x2bu rtw_switch_usb_mode=0 rtw_vht_enable=1 rtw_country_code=BO
EOF

# --- 7. PERSISTENCE CHECK ---
echo "[+] Verifying persistence partition mount..."
if mount | grep -q "persistence"; then
    echo "[PASS] Persistence is active. Changes will be saved."
else
    echo "[WARN] Persistence not detected! Did you select 'Persistence' in the boot menu?"
fi

echo "------------------------------------------------"
echo "[!] SURGERY COMPLETE. REBOOT TO FINALIZE."
echo "------------------------------------------------"
