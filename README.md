thesethese are actual real exploits however i dont know if they work hence unstable.
Since i dont have wpa3 of wpa2 with pmf on my router and my phones hotspot so maybe u could test it idkk
Iif it does work i will remove it bcuz of githubs policies.

Plus trust me bro wpa3 and pmf bypass is NOT possible especially by a normal person like me.



Future to do list if im not busy..
1. CSA multi.py
- Intended goal: Spam Channel Switch Announcements to force clients off the AP.
- Fail: Doesn’t coordinate with a fake AP on the target channel. Clients hop, see nothing, and return. So it’s just a hiccup, not a disconnect.
- Fix : Pair CSA with beacon spoofing on the destination channel.

2. OSV baiter.py
- Intended goal: Trick clients with Operating Mode/CSA variants.
- Fail: Same issue — no valid “bait” channel. It tells clients to move but doesn’t provide a believable AP there.
- Result: Clients ignore or recover instantly. It’s like yelling “go over there!” but pointing at an empty room.

3. Beacon spoofing.py
- Intended goal: Spam fake beacons to confuse clients.
- Fail: Beacons are unprotected, so spoofing is possible, but the script doesn’t maintain consistency (SSID, BSSID, channel alignment). Clients often reject inconsistent beacons.
- Result: At best, it clutters Wi-Fi scans. At worst, it just crashes the script itself.

4. Hellnah.py
- Intended goal: deauth/disassoc spam tool.
- Fail: WPA3/PMF protects deauth/disassoc frames. The script doesn’t check if PMF is enabled, so it just spams useless packets.
- Result: Works only on legacy WPA2 without PMF unless ignored.

5. Pretend cycle.py
- Intended goal: Rotate spoofed frames to simulate AP changes.
- Fail: No synchronization with real AP behavior. Clients see nonsense and ignore it.
