# =============================================================================
# VartaDNS - install as a container on MikroTik RouterOS v7
# =============================================================================
# Syntax follows the current RouterOS v7 manual (container envs/mounts use
# list=, container uses envlist= / mountlists=). On older v7 releases the
# parameter names differ (name= / mounts=) - check "/container/add ?" first.
#
# Run ONCE. Re-importing stops at the first "already exists" error; to start
# over run mikrotik-uninstall.rsc first.
#
# BEFORE YOU START (one-time, cannot be scripted):
#   1. Install the "container" package matching your RouterOS version and
#      architecture, then reboot. Keep it in sync on every RouterOS upgrade.
#   2. Enable container mode and confirm it physically within 5 minutes
#      (reset/mode button or power-cycle; a soft reboot cancels it):
#         /system/device-mode/update container=yes
#   3. Prepare the USB flash / disk. Containers need ext4 (FAT32 fails).
#      Use a quality 16-32 GB flash drive or a USB SSD.
#        /disk/print                                     # find the slot, e.g. usb1
#        /disk/format usb1 file-system=ext4 label=varta  # WARNING: erases the drive
#      Older RouterOS 7 releases name the command "format-drive":
#        /disk/format-drive usb1 file-system=ext4 label=varta
#      Verify it is mounted (flag M) and visible in files:
#        /disk/print
#        /file/print where name~"usb1"
#      If formatting fails with "device not available", create an empty
#      folder on the drive or format it as ext4 on a Linux PC.
#      Before unplugging: stop the container, then /disk/eject usb1
#   4. Upload the image for your CPU to the ext4 disk (Winbox Files or
#      scp vartadns-0.1.1-arm64.tar admin@192.168.88.1:/usb1/), then check
#      /file/print where name~"vartadns"
#        arm64 : CCR2004/2116/2216, RB5009, hAP ax2/ax3, L009
#        armv7 : RB4011, RB3011, hAP ac3 (256 MB RAM: use light lists only)
#        amd64 : CHR / x86
#      Devices with 128 MB RAM (hAP ac2 etc.) are NOT recommended.
#
# EDIT BEFORE IMPORT - every value marked "EDIT":
#   usb1                      -> your disk name (/disk print)
#   vartadns-0.1.1-arm64.tar  -> the uploaded image file name
#   192.168.88.0/24           -> your LAN subnet
#   192.168.88.1              -> the router's LAN address
#   LAN / WAN                 -> your interface lists (default config names)
#
# DESIGN: clients keep using the ROUTER as DNS (192.168.88.1). A dst-nat
# rule sends every DNS query to VartaDNS (clients keep their real source IP,
# so the panel shows per-device stats). If the container stops, netwatch
# disables the redirect and the router's own DNS answers, so the LAN never
# loses name resolution. It switches back automatically when VartaDNS is up.
#
# Run with:  /import file-name=mikrotik-install.rsc verbose=yes
# =============================================================================

# ---- 1. Container network: dedicated bridge + veth --------------------------
# br-containers must NOT be a member of the LAN interface list.
/interface/bridge/add name=br-containers comment="VartaDNS containers"
/ip/address/add address=172.17.53.1/24 interface=br-containers comment="VartaDNS gateway"
/interface/veth/add name=veth-varta address=172.17.53.2/24 gateway=172.17.53.1 comment="VartaDNS"
/interface/bridge/port/add bridge=br-containers interface=veth-varta

# Internet access for upstream DNS (DoH/Quad9) and blocklist downloads.
# The default config already masquerades out-interface-list=WAN; this rule
# is kept explicit so the setup also works on non-default configs.
# EDIT: WAN = your WAN interface list.
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.53.0/24 \
    out-interface-list=WAN comment="VartaDNS: container to internet"

# ---- 2. Environment and persistent storage ------------------------------------
# GOMEMLIMIT: Go runtime soft limit, keep it below memory-high (step 3:
# memory-high 256 MiB throttles, memory-max 320 MiB stops/restarts).
# Lower both on small routers (e.g. 120MiB / 150M with light lists).
/container/envs/add list=ENV_VARTA key=TZ value="Europe/Kyiv"
/container/envs/add list=ENV_VARTA key=GOMEMLIMIT value="200MiB"

# EDIT: usb1 -> your disk. /data keeps state.json (rules, lists, password
# hash) and downloaded blocklists across container re-creation.
/container/mounts/add list=MOUNT_VARTA src=usb1/vartadns/data dst=/data

# ---- 3. Create the container --------------------------------------------------
# EDIT: file= and root-dir= disk paths.
/container/add name=vartadns file=usb1/vartadns-0.1.1-arm64.tar \
    interface=veth-varta root-dir=usb1/vartadns/root \
    envlist=ENV_VARTA mountlists=MOUNT_VARTA dns=9.9.9.9 \
    start-on-boot=yes logging=yes restart-policy=on-failure restart-interval=10s \
    memory-high=268435456 memory-max=335544320 \
    comment="VartaDNS filtering DNS"

# Extraction takes a few seconds; wait for status "stopped", then:
#   /container/print
#   /container/start [find name=vartadns]
# First-run panel password (also see README: password reset):
#   /log/print where message~"credentials"

# ---- 4. Router DNS = fallback when VartaDNS is down ---------------------------------
# Clients query the router; the router itself uses Quad9 (never the
# container, to avoid a loop). The default config's input chain drops
# DNS from WAN ("drop all not coming from LAN") - keep it that way.
/ip/dns/set allow-remote-requests=yes servers=9.9.9.9,149.112.112.112

# EDIT: 192.168.88.0/24 and 192.168.88.1 -> your LAN subnet / router IP.
# Repeat for every DHCP network that should be filtered.
/ip/dhcp-server/network/set [find address=192.168.88.0/24] dns-server=192.168.88.1

# ---- 5. Redirect all plain DNS from LAN to VartaDNS -------------------------------
# Catches clients with hard-coded DNS (8.8.8.8 etc.) too. The container
# subnet is excluded so VartaDNS's own upstream queries never loop back.
# Added DISABLED: netwatch (step 6) enables them only after VartaDNS
# actually answers, so DNS never breaks during import or start-up.
# EDIT: LAN = your LAN interface list.
/ip/firewall/nat/add chain=dstnat in-interface-list=LAN protocol=udp dst-port=53 \
    src-address=!172.17.53.0/24 dst-address=!172.17.53.2 \
    action=dst-nat to-addresses=172.17.53.2 to-ports=53 disabled=yes comment="VartaDNS: force DNS (udp)"
/ip/firewall/nat/add chain=dstnat in-interface-list=LAN protocol=tcp dst-port=53 \
    src-address=!172.17.53.0/24 dst-address=!172.17.53.2 \
    action=dst-nat to-addresses=172.17.53.2 to-ports=53 disabled=yes comment="VartaDNS: force DNS (tcp)"

# ---- 6. Failover: disable the redirect while VartaDNS is not answering --------------
# tcp-conn checks the container itself and does not depend on the internet.
# startup-delay=0s: the default is 5 minutes after boot, during which the
# redirect would stay in its saved state even if VartaDNS is not up yet.
# Removing conntrack entries makes clients that reuse one UDP source port
# (IoT, some stub resolvers) switch immediately instead of hitting the
# old NAT mapping. After a reboot netwatch starts in "unknown" state and
# runs up-script or down-script on its first probe, so the redirect always
# matches the real container state within ~10 s.
/tool/netwatch/add type=tcp-conn host=172.17.53.2 port=53 interval=10s \
    startup-delay=0s thr-tcp-conn-time=2s \
    down-script="/ip/firewall/nat/disable [find comment~\"VartaDNS: force DNS\"]; /ip/firewall/connection/remove [find reply-src-address=172.17.53.2 protocol=udp]; :log warning \"VartaDNS down: router DNS fallback\"" \
    up-script="/ip/firewall/nat/enable [find comment~\"VartaDNS: force DNS\"]; /ip/firewall/connection/remove [find dst-port=53 protocol=udp]; :log info \"VartaDNS up: filtering active\"" \
    comment="VartaDNS failover"

# ---- 7. Block encrypted DNS that would bypass the filter --------------------------
# DoT / DoQ (port 853) from LAN. tcp-reset makes clients fall back at once.
/ip/firewall/filter/add chain=forward in-interface-list=LAN protocol=tcp dst-port=853 \
    action=reject reject-with=tcp-reset comment="VartaDNS: block DoT"
/ip/firewall/filter/add chain=forward in-interface-list=LAN protocol=udp dst-port=853 \
    action=drop comment="VartaDNS: block DoQ"

# DoH to well-known public resolvers (not complete - extend as needed).
# Only LAN traffic is matched; VartaDNS's own DoH upstream is not affected.
/ip/firewall/address-list
add list=doh-servers address=8.8.8.8 comment="Google"
add list=doh-servers address=8.8.4.4 comment="Google"
add list=doh-servers address=1.1.1.1 comment="Cloudflare"
add list=doh-servers address=1.0.0.1 comment="Cloudflare"
add list=doh-servers address=9.9.9.9 comment="Quad9"
add list=doh-servers address=149.112.112.112 comment="Quad9"
add list=doh-servers address=94.140.14.14 comment="AdGuard"
add list=doh-servers address=94.140.15.15 comment="AdGuard"
add list=doh-servers address=208.67.222.222 comment="OpenDNS"
add list=doh-servers address=208.67.220.220 comment="OpenDNS"
add list=doh-servers address=45.90.28.0/24 comment="NextDNS"
add list=doh-servers address=45.90.30.0/24 comment="NextDNS"
/ip/firewall/filter/add chain=forward in-interface-list=LAN protocol=tcp dst-port=443 \
    dst-address-list=doh-servers action=reject reject-with=tcp-reset \
    comment="VartaDNS: block DoH (tcp)"
/ip/firewall/filter/add chain=forward in-interface-list=LAN protocol=udp dst-port=443 \
    dst-address-list=doh-servers action=drop comment="VartaDNS: block DoH (QUIC/HTTP3)"

# ---- 8. IPv6: stop clients from bypassing the filter over IPv6 ---------------------
# Stop advertising the router's IPv6 DNS via RA, and block DNS/DoT/DoQ to
# the internet over IPv6. Clients then use the IPv4 DNS from DHCP.
# Harmless if IPv6 is not used.
/ipv6/nd/set [find] advertise-dns=no
/ipv6/firewall/filter/add chain=forward in-interface-list=LAN protocol=udp dst-port=53 \
    action=drop comment="VartaDNS: block IPv6 DNS"
/ipv6/firewall/filter/add chain=forward in-interface-list=LAN protocol=tcp dst-port=53 \
    action=reject reject-with=tcp-reset comment="VartaDNS: block IPv6 DNS (tcp)"
/ipv6/firewall/filter/add chain=forward in-interface-list=LAN protocol=tcp dst-port=853 \
    action=reject reject-with=tcp-reset comment="VartaDNS: block IPv6 DoT"
/ipv6/firewall/filter/add chain=forward in-interface-list=LAN protocol=udp dst-port=853 \
    action=drop comment="VartaDNS: block IPv6 DoQ"

# ---- 9. Protect the web panel: only the admin subnet may open :8080 ------------------
# EDIT: 192.168.88.0/24 -> your admin subnet.
/ip/firewall/filter/add chain=forward protocol=tcp dst-address=172.17.53.2 dst-port=8080 \
    src-address=!192.168.88.0/24 action=drop comment="VartaDNS: panel admin-only"

# ---- IMPORTANT: rule order ------------------------------------------------------------
# New filter rules are appended to the END of their chain. If the forward
# chain has a broad "accept" above them, move the VartaDNS rules up
# (Winbox drag & drop, or /ip/firewall/filter/move). Check with:
#   /ip/firewall/filter/print where comment~"VartaDNS"
#   /ipv6/firewall/filter/print where comment~"VartaDNS"
#
# Panel: http://172.17.53.2:8080  (user admin, password from the log)
