#!/system/bin/sh
# CHANGE 01 experiment: stage-1 only (write perf_event_paranoid=-1) and DO NOTHING else.
# No exploit, no markers cleanup (the payload owns them for this boot).
D=/data/local/tmp
exec >> $D/gl.exp.log 2>&1
echo "=== glboot_exp $(date) uid=$(id -u) ctx=$(cat /proc/self/attr/current 2>/dev/null) ==="
if [ "$(id -u)" = "0" ]; then
    echo -1 > /proc/sys/kernel/perf_event_paranoid
    echo "perf_after=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null)"
fi
exit 0
