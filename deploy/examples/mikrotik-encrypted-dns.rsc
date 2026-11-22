# =============================================================================
# VartaDNS: allow encrypted DNS (DoH 443 / DoT 853) from the LAN to VartaDNS
# (optional, RouterOS 7). Run after enabling DoH/DoT in the VartaDNS panel.
#
# The base install blocks DoT (tcp/853) from the LAN to everywhere, so
# clients could not reach VartaDNS's own DoT. This exempts the container.
# DoH to VartaDNS (172.17.53.2:443) is not blocked by the base install
# (only known public resolvers are), so nothing else is needed in the LAN.
#
# Run with:  /import file-name=mikrotik-encrypted-dns.rsc verbose=yes
# Undo:      /ip/firewall/filter/unset [find comment="VartaDNS: block DoT"] dst-address
# =============================================================================

:if ([:len [/ip/firewall/filter/find where comment="VartaDNS: block DoT"]] = 0) do={
    :put "WARNING: rule 'VartaDNS: block DoT' not found - nothing to change."
} else={
    /ip/firewall/filter/set [find comment="VartaDNS: block DoT"] dst-address=!172.17.53.2
    :put "OK: DoT to VartaDNS (172.17.53.2:853) is allowed, other DoT stays blocked."
}

# ---- Check ------------------------------------------------------------------------
#   /ip/firewall/filter/print where comment~"VartaDNS: block DoT"
#
# Access from outside the home (mobile data) needs port forwarding of
# 443/853 from WAN to 172.17.53.2 and a public DNS record for the name.
# Only personal addresses (token) are accepted from outside the LAN ACL,
# but the ports become visible on the internet: not set up here on purpose.
