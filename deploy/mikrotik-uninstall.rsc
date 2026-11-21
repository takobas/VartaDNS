# =============================================================================
# VartaDNS - remove everything mikrotik-install.rsc created
# =============================================================================
# Files on the disk (usb1/vartadns/...) are NOT deleted: remove them
# manually if you no longer need the rules/lists/password state.
# The router DNS settings from step 4 (allow-remote-requests, servers) and
# DHCP dns-server are left as they are - the LAN keeps working through the
# router's own DNS. IPv6 "advertise-dns" stays disabled; re-enable it with
#   /ipv6/nd/set [find] advertise-dns=yes
# if you want.
#
# Run with:  /import file-name=mikrotik-uninstall.rsc verbose=yes
# =============================================================================

# Stop redirecting DNS first so clients fall back to the router immediately.
/ip/firewall/nat/remove [find comment~"VartaDNS"]
/tool/netwatch/remove [find comment="VartaDNS failover"]
/ip/firewall/filter/remove [find comment~"VartaDNS"]
/ipv6/firewall/filter/remove [find comment~"VartaDNS"]
/ip/firewall/address-list/remove [find list=doh-servers]

# Container: stop, wait, remove.
/container/stop [find name=vartadns]
:delay 5s
/container/remove [find name=vartadns]
/container/mounts/remove [find list=MOUNT_VARTA]
/container/envs/remove [find list=ENV_VARTA]

# Network.
/interface/bridge/port/remove [find interface=veth-varta]
/interface/veth/remove [find name=veth-varta]
/ip/address/remove [find comment="VartaDNS gateway"]
/interface/bridge/remove [find name=br-containers]
