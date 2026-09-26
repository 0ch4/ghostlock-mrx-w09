#!/system/bin/sh
# N2 staging: populate the overlay upper dirs with the Google-signed priv-apps + XMLs and
# label them system_file.  Idempotent: the (135MB) copy happens ONCE into a PERSISTENT
# /data dir; later boots reuse it, so the restore no longer recopies 135MB every time.
#
# $1 = the upperdir base (default: the old tmpfs path for compatibility).
set -x
B="${1:-/data/local/tmp/glrt/gms}"
S=/data/local/tmp/gms_stage
NEED="$B/upper-priv/PrebuiltGmsCore/PrebuiltGmsCore.apk"
if [ -s "$NEED" ]; then
    echo "already staged: $B (skip the 135MB copy)"
else
    rm -rf "$B"
    mkdir -p "$B/upper-priv/PrebuiltGmsCore" "$B/upper-priv/GoogleServicesFramework" "$B/upper-priv/Phonesky" \
             "$B/work-priv" "$B/upper-perm" "$B/work-perm" "$B/upper-sys" "$B/work-sys"
    cp "$S/priv-app/PrebuiltGmsCore/PrebuiltGmsCore.apk"           "$B/upper-priv/PrebuiltGmsCore/"
    cp "$S/priv-app/GoogleServicesFramework/GoogleServicesFramework.apk" "$B/upper-priv/GoogleServicesFramework/"
    cp "$S/priv-app/Phonesky/Phonesky.apk"                         "$B/upper-priv/Phonesky/"
    cp "$S"/permissions/*.xml "$B/upper-perm/"
    cp "$S"/sysconfig/*.xml    "$B/upper-sys/"
fi
chown -R 0:0 "$B"
chmod -R a+rX "$B"
chcon -R u:object_r:system_file:s0 "$B"
echo "=== upper-priv ==="
ls -laZ "$B/upper-priv" "$B/upper-priv/"*
sync
echo DONE
