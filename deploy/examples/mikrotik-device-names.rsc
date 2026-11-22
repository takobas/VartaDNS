# =============================================================================
# VartaDNS: device names from DHCP (optional, RouterOS 7)
#
# What it does:
#   1. Every 5 minutes copies the host names of bound DHCP leases into the
#      router's DNS as static A records "<hostname>.lan" (comment varta-dhcp).
#      RouterOS answers reverse (PTR) queries for static A records
#      automatically, so VartaDNS can ask "who is 192.168.11.45?".
#      Records are only added/removed when something changed (no flash wear).
#   2. Allows the VartaDNS container to query the router's DNS
#      (172.17.53.1:53). The container bridge is not in the LAN list, so the
#      default "drop all not coming from LAN" rule would block it.
#
# Then in the VartaDNS panel: Devices -> Names server = 172.17.53.1 -> Save.
#
# Run with:  /import file-name=mikrotik-device-names.rsc verbose=yes
# Undo: see the end of this file.
# =============================================================================

# ---- 1. Sync script -----------------------------------------------------------
/system/script/remove [find name=varta-dhcp-names]
/system/script/add name=varta-dhcp-names policy=read,write,test \
    comment="VartaDNS: DHCP host names to DNS" source={
    :local domain "lan"
    :local tag "varta-dhcp"
    :local up "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    :local lo "abcdefghijklmnopqrstuvwxyz"
    :local ok "abcdefghijklmnopqrstuvwxyz0123456789-"
    :local want [:toarray ""]
    :local have [:toarray ""]
    # Collect name -> address from bound leases that have a host name.
    :foreach l in=[/ip/dhcp-server/lease/find where status="bound" and host-name!=""] do={
        :local hn [:tostr [/ip/dhcp-server/lease/get $l host-name]]
        :local ip [/ip/dhcp-server/lease/get $l active-address]
        # Guard: an empty string would make the for loop below count down.
        :if ([:len $hn] > 0 and [:len $hn] <= 63 and [:typeof $ip] = "ip") do={
            # Lowercase; keep a-z, 0-9 and hyphen, anything else becomes a hyphen.
            :local clean ""
            :for i from=0 to=([:len $hn] - 1) do={
                :local c [:pick $hn $i ($i + 1)]
                :local p [:find $up $c]
                :if ([:typeof $p] = "num") do={ :set c [:pick $lo $p ($p + 1)] }
                :if ([:typeof [:find $ok $c]] != "num") do={ :set c "-" }
                :set clean ($clean . $c)
            }
            # Strip leading and trailing hyphens (a non-conforming name would be treated as a regexp).
            :while ([:len $clean] > 0 and [:pick $clean 0 1] = "-") do={
                :set clean [:pick $clean 1 [:len $clean]]
            }
            :while ([:len $clean] > 0 and [:pick $clean ([:len $clean] - 1) [:len $clean]] = "-") do={
                :set clean [:pick $clean 0 ([:len $clean] - 1)]
            }
            :if ([:len $clean] > 0) do={
                :set ($want->($clean . "." . $domain)) $ip
            }
        }
    }
    # Remove records that are gone, point to another address now, or are duplicates.
    :foreach e in=[/ip/dns/static/find where comment=$tag] do={
        :local n [/ip/dns/static/get $e name]
        :local a [/ip/dns/static/get $e address]
        :if ([:typeof ($want->$n)] = "nothing" or [:typeof ($have->$n)] != "nothing") do={
            /ip/dns/static/remove $e
        } else={
            :if ([:tostr ($want->$n)] != [:tostr $a]) do={
                /ip/dns/static/remove $e
            } else={
                :set ($have->$n) 1
            }
        }
    }
    # Add missing records; one bad name must not abort the whole run.
    :foreach n,a in=$want do={
        :if ([:typeof ($have->$n)] = "nothing") do={
            :do {
                /ip/dns/static/add name=$n address=$a ttl=5m comment=$tag
            } on-error={ :log warning ("varta-dhcp-names: cannot add " . $n) }
        }
    }
}

/system/scheduler/remove [find name=varta-dhcp-names]
/system/scheduler/add name=varta-dhcp-names interval=5m start-time=startup \
    on-event="/system/script/run varta-dhcp-names" policy=read,write,test \
    comment="VartaDNS: DHCP host names to DNS"

# First run right away. Wrapped so a script error does not stop the import
# before the firewall rule below is added.
:do { /system/script/run varta-dhcp-names } on-error={ :put "WARNING: first run of varta-dhcp-names failed, see /log" }

# ---- 2. Let the container ask the router's DNS ----------------------------------------
/ip/firewall/filter/remove [find comment="VartaDNS: device names (PTR) from container"]
:if ([:len [/ip/firewall/filter/find where chain=input and comment~"drop all not coming from LAN"]] > 0) do={
    /ip/firewall/filter/add chain=input in-interface=br-containers src-address=172.17.53.2 \
        protocol=udp dst-port=53 action=accept \
        comment="VartaDNS: device names (PTR) from container" \
        place-before=[:pick [/ip/firewall/filter/find where chain=input and comment~"drop all not coming from LAN"] 0]
} else={
    /ip/firewall/filter/add chain=input in-interface=br-containers src-address=172.17.53.2 \
        protocol=udp dst-port=53 action=accept \
        comment="VartaDNS: device names (PTR) from container"
    :put "WARNING: default drop rule not found. Move the new accept rule above your input drop rule."
}

# ---- Check --------------------------------------------------------------------------
#   /ip/dns/static/print where comment=varta-dhcp
#   VartaDNS panel -> Devices: the "From router" column fills within ~5 min.
#
# ---- Undo ---------------------------------------------------------------------------
#   /system/scheduler/remove [find name=varta-dhcp-names]
#   /system/script/remove [find name=varta-dhcp-names]
#   /ip/dns/static/remove [find comment=varta-dhcp]
#   /ip/firewall/filter/remove [find comment="VartaDNS: device names (PTR) from container"]
