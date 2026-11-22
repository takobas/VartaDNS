# =============================================================================
# VartaDNS - update the container on hAP ac2 to 0.3.0 (keeps all settings)
# =============================================================================
# Run these commands ONE BLOCK AT A TIME in the terminal (not with /import):
# some steps must wait for the container to stop, disappear or extract.
#
# What should be kept: usb1/vartadns/data (state.json with groups, custom
# rules, lists, users, Telegram; downloaded lists; since 0.3.0 also logs/,
# tls/, devices.json, daily.json, audit.log). It is a separate mount
# next to the root-dir, not inside it. RouterOS docs do not state what
# /container/remove deletes, so step 0 makes a backup first.
# Envs (ENV_VARTA), mounts (MOUNT_VARTA), network, NAT, netwatch and
# firewall rules are not touched.
#
# DNS during the update: netwatch notices VartaDNS is down within ~10-15 s
# and switches clients to the router's own DNS, then back when the new
# version answers. Expect up to ~10-15 s of failed lookups twice (when it
# stops and when it comes back); during extraction the router answers.
#
# NEVER use /file/remove with a pattern like name~"usb1/vartadns" - it
# also matches usb1/vartadns/data with all your settings.
# =============================================================================

# ---- 0. Preparation --------------------------------------------------------------
# a) Backup of the settings: in Winbox > Files open usb1/vartadns/data and
#    download state.json to your PC (drag & drop), or from the PC:
#      scp admin@192.168.11.1:/usb1/vartadns/data/state.json ./state-backup.json
#    From 0.3.0 on the panel also has Settings > Backup (download a copy).
# b) Upload usb1/vartadns-0.3.0-armv7.tar (Winbox Files) and check:
/file/print where name~"vartadns-0.3.0"
# c) Extraction must go to the flash, not the 16 MB internal storage:
/container/config/print
/container/config/set tmpdir=usb1/tmp
# d) Note the CURRENT image file and root-dir (needed for rollback and step 5;
#    they may differ from the names below if you installed differently):
/container/print detail where name=vartadns
# e) Free space: free-hdd-space (internal) and FREE of usb1 (needs room for
#    the new image plus a second root-dir, ~30 MB):
/system/resource/print
/disk/print

# ---- 1. Stop the running container ---------------------------------------------------
/container/stop [find name=vartadns]
# Wait until the R (RUNNING) flag is gone:
/container/print
# If R is still shown after ~30 s:
#   /container/kill [find name=vartadns]

# ---- 2. Remove the old container definition --------------------------------------------
/container/remove [find name=vartadns]
# Removal can take a while (D flag). Wait until vartadns is no longer listed,
# otherwise the next "add" fails on the duplicate name:
/container/print
# Check the settings are still there:
/file/print where name~"usb1/vartadns/data"
# If remove fails with "action timed out", simply run it again.

# ---- 3. Create it again from the new image -----------------------------------------------
# A new root-dir is used so old extracted files can never clash with the new
# image. Same envs, mounts and limits as the original install.
/container/add name=vartadns file=usb1/vartadns-0.3.0-armv7.tar \
    interface=veth-varta root-dir=usb1/vartadns/root-030 \
    envlist=ENV_VARTA mountlists=MOUNT_VARTA dns=9.9.9.9 \
    start-on-boot=yes logging=yes restart-policy=on-failure restart-interval=10s \
    memory-high=58720256 memory-max=67108864 \
    comment="VartaDNS filtering DNS"
# Wait until extraction finishes (USB 2.0 flash: 1-2 minutes):
/container/print

# ---- 4. Start and verify -----------------------------------------------------------------------
/container/start [find name=vartadns]
# After ~30 s:
/log/print where message~"VartaDNS 0.3.0|lists rebuilt|VartaDNS up"
/tool/netwatch/print where comment="VartaDNS failover"
# The panel must show the new "Devices" tab and your rules/password unchanged.

# ---- 4b. Firewall for the new panel HTTPS port (8443) -----------------------------------
# The panel rule from the install covered only 8080:
/ip/firewall/filter/set [find comment="VartaDNS: panel admin-only"] dst-port=8080,8443
# Optional, see the panel and the guide (upload the .rsc file first; if it is
# on the flash, use file-name=usb1/<name>.rsc):
#   device names from DHCP:   /import file-name=mikrotik-device-names.rsc verbose=yes
#   DoT to VartaDNS allowed:  /import file-name=mikrotik-encrypted-dns.rsc verbose=yes
# If state.json was lost, copy the backup from step 0 back to
# usb1/vartadns/data/state.json (container stopped) and start again.

# ---- ROLLBACK to 0.2.3 (only if 0.3.0 does not start) -----------------------------------
#   /container/stop [find name=vartadns]
#   /container/remove [find name=vartadns]
#   (wait until it is gone: /container/print)
#   (use the tar file noted in step 0d; a fresh root-dir avoids old files)
#   /container/add name=vartadns file=usb1/vartadns-0.2.3-armv7.tar \
#       interface=veth-varta root-dir=usb1/vartadns/root-023 \
#       envlist=ENV_VARTA mountlists=MOUNT_VARTA dns=9.9.9.9 \
#       start-on-boot=yes logging=yes restart-policy=on-failure restart-interval=10s \
#       memory-high=58720256 memory-max=67108864 comment="VartaDNS filtering DNS"
#   /container/start [find name=vartadns]
# 0.2.3 ignores the new fields in state.json (users, Telegram, logs...) and
# logs in with the admin password. Do not change settings in the panel while
# on 0.2.3: saving would drop the new fields (restore the step 0 backup).

# ---- 5. Cleanup - only after 0.3.0 has worked fine for a day -------------------------------
# Old tar file (keep it until then - it is your rollback):
#   /file/remove [find name="usb1/vartadns-0.2.3-armv7.tar"]
# Old extracted image = the root-dir noted in step 0d (exact name, no ~ pattern!),
# e.g. if it was usb1/vartadns/root-023:
#   /file/remove [find name="usb1/vartadns/root-023"]
# Never delete usb1/vartadns/data - it holds your settings.
