package com.ghostlock.manager;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * GhostLock Restore (MRX-W09) - cold-boot, PC-less, tap-driven restore front-end.
 *
 * What this app can and cannot do (measured; see the FACTS log 9an(157)/(158)/(160)/(164)):
 *
 *   CAN   : run the Mali page-cache writer (assets/inject_hook) from its own data dir
 *           (targetSdk 27 -> untrusted_app_27 has app_data_file execute_no_trans);
 *           read /system/lib64/libc.so, so it can VERIFY that the hook really landed;
 *           write to an EXISTING file in /data/local/tmp (allow appdomain shell_data_file
 *           (file (write getattr))) so it can keep the payload/script in sync;
 *           start Settings (android.settings.APPLICATION_DEVELOPMENT_SETTINGS).
 *
 *   CANNOT: execute the kernel exploit (app seccomp-BPF is inherited across fork/exec and
 *           blocks mount(2) etc. -> 9an(158)); send ACTION_BUGREPORT (needs DUMP);
 *           connect to the dumpstate socket (0660 shell:log);
 *           create/unlink/rename anything in /data/local/tmp (neverallow).
 *
 * So the restore itself is executed by the SYSTEM's own bug-report path:
 *   Developer options -> "Take bug report" -> com.android.shell runs bugreportz as uid 2000
 *   in the SHELL DOMAIN and init starts dumpstate as uid 0.  Both call open64, both hit the
 *   hook, and the two-stage payload runs glboot.sh in the right context (uid 0 writes
 *   perf_event_paranoid; uid 2000/shell execs the exploit and does the GMS overlays).
 *
 * NEVER call `inject_hook restore` on the same boot: running the Mali writer a second time
 * reset the device (9an(164)D).  The hook lives in the page cache and dies at reboot.
 */
public class MainActivity extends Activity {

    // ---- libc.so facts (the enabler's target) ------------------------------------------
    private static final String LIBC    = "/system/lib64/libc.so";
    private static final long   OFF_HOOK = 0x7a3d4L;   // first insn of open64
    private static final long   OFF_CAVE = 0x84000L;   // where the payload is copied
    private static final byte[] HOOKED   = { 0x0b, 0x27, 0x00, 0x14 };            // b 0x84000
    private static final byte[] ORIGINAL = { (byte)0xff, 0x03, 0x04, (byte)0xd1 };

    private static final String D       = "/data/local/tmp";
    private static final String PAYLOAD = "shellcode.bin";
    private static final String GLBOOT  = "glboot.sh";

    // Assets we keep on the device so the payload and its script always match this APK.
    // inject_hook is NOT synced: the app keeps its own copy in filesDir and the device's
    // /data/local/tmp/inject_hook is 0755, which the app cannot open for writing (EACCES).
    private static final String[] SYNC_ASSETS = { "shellcode.bin", "glboot.sh", "gms_setup.sh" };

    private final Handler ui = new Handler(Looper.getMainLooper());
    private TextView statusView, logView, hintView, titleView;
    private ScrollView logScroll;
    // Per-action running flags (NOT one global flag): one hung action must not freeze
    // every button (DESIGN 9.1).  A duplicate tap of the SAME action is ignored, but a
    // different button still works while one op is in flight.
    private final ConcurrentHashMap<String, Boolean> running = new ConcurrentHashMap<String, Boolean>();
    private boolean beginAction(String k) { return running.putIfAbsent(k, Boolean.TRUE) == null; }
    private void endAction(String k) { running.remove(k); }

    // ------------------------------------------------------------------------------ UI
    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xff0b0f14);
        root.setPadding(28, 24, 28, 20);

        titleView = new TextView(this);
        titleView.setText("GhostLock Restore  (MRX-W09)");
        titleView.setTextColor(0xff35d07f);
        titleView.setTextSize(22);
        titleView.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(titleView, lp(-2, -2, 0, 0, 0, 10));

        statusView = new TextView(this);
        statusView.setTextColor(0xffe6e6e6);
        statusView.setTextSize(14);
        statusView.setTypeface(Typeface.MONOSPACE);
        statusView.setPadding(18, 18, 18, 18);
        statusView.setBackgroundColor(0xff141b24);
        root.addView(statusView, lp(-1, -2, 0, 0, 0, 12));

        LinearLayout row1 = new LinearLayout(this);
        row1.setOrientation(LinearLayout.HORIZONTAL);
        row1.addView(button("(1) hook を張る", 0xff2563eb, new Runnable() { public void run() { armHook(); } }));
        row1.addView(button("(2) 開発者向けオプション", 0xffb45309, new Runnable() { public void run() { openDevOptions(); } }));
        root.addView(row1, lp(-1, -2, 0, 0, 0, 8));

        LinearLayout row1b = new LinearLayout(this);
        row1b.setOrientation(LinearLayout.HORIZONTAL);
        row1b.addView(button("★ 復元 (1操作)", 0xff16a34a, new Runnable() { public void run() { oneShotRestore(); } }));
        row1b.addView(button("0タップ検証", 0xff7c3aed, new Runnable() { public void run() { probeAppTrigger(); } }));
        root.addView(row1b, lp(-1, -2, 0, 0, 0, 8));

        LinearLayout row2 = new LinearLayout(this);
        row2.setOrientation(LinearLayout.HORIZONTAL);
        row2.addView(button("(3) 状態を更新", 0xff374151, new Runnable() { public void run() { refreshStatus(); } }));
        row2.addView(button("(4) 同期", 0xff374151, new Runnable() { public void run() { syncFiles(); } }));
        row2.addView(button("(5) ログ", 0xff374151, new Runnable() { public void run() { showLog(); } }));
        root.addView(row2, lp(-1, -2, 0, 0, 0, 8));

        LinearLayout row2b = new LinearLayout(this);
        row2b.setOrientation(LinearLayout.HORIZONTAL);
        row2b.addView(button("a11y自動タップ設定", 0xff0e7490, new Runnable() { public void run() { openA11ySettings(); } }));
        row2b.addView(button("a11y状態", 0xff374151, new Runnable() { public void run() { checkA11y(); } }));
        root.addView(row2b, lp(-1, -2, 0, 0, 0, 12));

        hintView = new TextView(this);
        hintView.setTextColor(0xff9fb3c8);
        hintView.setTextSize(13);
        hintView.setText(
            "手順: (1) hook を張る → (2) 開発者向けオプションを開き「バグレポートを取得」をタップ → 数十秒待つ\n" +
            "      → (3) 状態を更新（perf=-1 / GMS 3/3 なら復元成功）\n" +
            "再起動すると overlay は消えます（RAM のため）。毎回 (1) からやり直してください。\n" +
            "※ このアプリは root を取れません（app seccomp）。復元は system のバグレポート経路が実行します。");
        root.addView(hintView, lp(-1, -2, 0, 0, 0, 12));

        logView = new TextView(this);
        logView.setTextColor(0xffc7d2da);
        logView.setTextSize(12);
        logView.setTypeface(Typeface.MONOSPACE);
        logView.setPadding(14, 14, 14, 14);
        logView.setBackgroundColor(0xff0f141a);
        logView.setMovementMethod(new ScrollingMovementMethod());
        logScroll = new ScrollView(this);
        logScroll.addView(logView);
        root.addView(logScroll, new LinearLayout.LayoutParams(-1, 0, 1f));

        setContentView(root);
        log("app started; filesDir=" + getFilesDir());
        refreshStatus();
    }

    private LinearLayout.LayoutParams lp(int w, int h, int l, int t, int r, int bo) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(w, h);
        p.setMargins(l, t, r, bo);
        return p;
    }

    private Button button(String label, int color, final Runnable action) {
        Button b = new Button(this);
        b.setText(label);
        b.setTextSize(14);
        b.setAllCaps(false);
        b.setBackgroundColor(color);
        b.setTextColor(0xffffffff);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(0, -2, 1f);
        p.setMargins(0, 0, 8, 0);
        b.setLayoutParams(p);
        b.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { action.run(); }
        });
        return b;
    }

    // ------------------------------------------------------------------------ plumbing
    private void post(final String s) {
        ui.post(new Runnable() { public void run() { logView.append(s + "\n"); } });
    }

    private void log(String s) {
        String t = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        android.util.Log.i("GhostLock", s);          // also visible via: adb logcat -s GhostLock
        post(t + "  " + s);
        ui.post(new Runnable() { public void run() { logScroll.post(new Runnable() { public void run() { logScroll.fullScroll(View.FOCUS_DOWN); } }); } });
    }

    private void setStatus(final String s) {
        ui.post(new Runnable() { public void run() { statusView.setText(s); } });
    }

    private void bg(final String name, final Runnable r) {
        if (!beginAction(name)) { log("(" + name + " is already running)"); return; }
        new Thread(new Runnable() {
            public void run() {
                try { r.run(); }
                catch (Throwable t) { log(name + " ERROR " + t); }
                finally { endAction(name); }
            }
        }, name).start();
    }

    // ------------------------------------------------------------------------ state
    private File extract(String name, boolean exec) throws Exception {
        File out = new File(getFilesDir(), name);
        InputStream in = getAssets().open(name);
        FileOutputStream fo = new FileOutputStream(out, false);   // our own dir: create is fine
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) fo.write(buf, 0, n);
        fo.close();
        in.close();
        if (exec) { out.setExecutable(true, false); out.setReadable(true, false); }
        return out;
    }

    /** Read an asset fully (the APK is the source of truth for the payload/scripts). */
    private byte[] assetBytes(String name) {
        try {
            InputStream in = getAssets().open(name);
            byte[] b = new byte[in.available()];
            int rd = 0, n;
            while (rd < b.length && (n = in.read(b, rd, b.length - rd)) > 0) rd += n;
            in.close();
            return b;
        } catch (Throwable t) {
            return null;
        }
    }

    private long assetSize(String name) {
        byte[] b = assetBytes(name);
        return b == null ? -1 : b.length;
    }

    /** Read the payload that is really on the device (/data/local/tmp/shellcode.bin).
     *  Everything (the branch-back offset ph, the "is it placed" check) must come from
     *  THIS file, because that is what inject_hook reads when it patches libc. */
    private byte[] readDevicePayload() {
        try {
            File f = new File(D, PAYLOAD);
            if (!f.exists()) return null;
            byte[] b = new byte[(int) f.length()];
            FileInputStream in = new FileInputStream(f);
            int rd = 0, n;
            while (rd < b.length && (n = in.read(b, rd, b.length - rd)) > 0) rd += n;
            in.close();
            if (rd != b.length) { byte[] t = new byte[rd]; System.arraycopy(b, 0, t, 0, rd); return t; }
            return b;
        } catch (Throwable t) {
            return null;
        }
    }

    private static String exec(String[] cmd, File dir) { return exec(cmd, dir, 0); }

    /** Run a command.  If timeoutMs>0 this is the exec WATCHDOG: the child is killed on
     *  timeout and a TIMEOUT line is reported, so one hung helper cannot freeze the app
     *  (DESIGN 9.1).  Output is drained on a daemon thread so a hung child cannot block us. */
    private static String exec(String[] cmd, File dir, long timeoutMs) {
        StringBuilder sb = new StringBuilder();
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            if (dir != null) pb.directory(dir);
            pb.redirectErrorStream(true);
            final Process p = pb.start();
            final StringBuilder ob = new StringBuilder();
            Thread reader = new Thread(new Runnable() { public void run() {
                try {
                    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
                    String l; while ((l = r.readLine()) != null) ob.append(l).append('\n');
                } catch (Throwable t) { /* ignore */ }
            }});
            reader.setDaemon(true); reader.start();
            if (timeoutMs > 0) {
                if (!p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
                    p.destroyForcibly();
                    try { reader.join(2000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                    sb.append(ob).append("[TIMEOUT after ").append(timeoutMs).append("ms - child killed]\n");
                    return sb.toString();
                }
            } else {
                p.waitFor();
            }
            try { reader.join(2000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            sb.append(ob).append("[exit=").append(p.exitValue()).append("]\n");
        } catch (Throwable t) {
            sb.append("exec failed: ").append(t).append('\n');
        }
        return sb.toString();
    }

    private byte[] libc(long off, int n) {
        try {
            RandomAccessFile f = new RandomAccessFile(LIBC, "r");
            byte[] b = new byte[n];
            f.seek(off);
            f.readFully(b);
            f.close();
            return b;
        } catch (Throwable t) {
            return null;
        }
    }

    private static boolean eq(byte[] a, byte[] b, int n) {
        if (a == null || b == null || a.length < n || b.length < n) return false;
        for (int i = 0; i < n; i++) if (a[i] != b[i]) return false;
        return true;
    }

    private static String hex(byte[] b) {
        if (b == null) return "??";
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    private static String readFile(String path, int maxLines) {
        StringBuilder sb = new StringBuilder();
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(path)));
            String l;
            int i = 0;
            while ((l = r.readLine()) != null && i++ < maxLines) sb.append(l).append('\n');
            r.close();
        } catch (Throwable t) {
            return "(cannot read " + path + ": " + t + ")";
        }
        return sb.toString();
    }

    private static long countIn(String path, String needle) {
        long c = 0;
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(path)));
            String l;
            while ((l = r.readLine()) != null) if (l.contains(needle)) c++;
            r.close();
        } catch (Throwable t) {
            return -1;
        }
        return c;
    }

    /** Read a one-line value from a file (perf_event_paranoid etc.). Returns null on failure. */
    private static String readOneLine(String path) {
        try {
            BufferedReader r = new BufferedReader(new InputStreamReader(new FileInputStream(path)));
            String l = r.readLine();
            r.close();
            return l == null ? null : l.trim();
        } catch (Throwable t) {
            return null;
        }
    }

    private static boolean exists(String p) { return new File(p).exists(); }

    private static long sizeOf(String p) {
        File f = new File(p);
        return f.exists() ? f.length() : -1;
    }

    // ------------------------------------------------------------------------ actions
    private void refreshStatus() {
        bg("status", new Runnable() {
            public void run() {
                StringBuilder s = new StringBuilder();
                try {
                    // Verify against the payload that is ACTUALLY on the device, not the
                    // APK asset: the payload gets replaced as we iterate, and a size
                    // mismatch would make `place <ph>` wrong.  The bundled asset is only
                    // used by the "sync" button to repair the device copy.
                    byte[] devPayload = readDevicePayload();
                    byte[] devHead = new byte[16];
                    if (devPayload != null && devPayload.length >= 16) System.arraycopy(devPayload, 0, devHead, 0, 16);
                    byte[] cave = libc(OFF_CAVE, 16);
                    byte[] hook = libc(OFF_HOOK, 4);

                    s.append("payload   : ").append(devPayload == null ? "MISSING" : (devPayload.length + " B"));
                    s.append("  libc@0x84000 = ").append(hex(cave)).append(eq(cave, devHead, 16) ? "   [placed OK]\n" : "   [NOT placed]\n");
                    s.append("hook      : libc@0x7a3d4 = ").append(hex(hook));
                    if (eq(hook, HOOKED, 4)) s.append("   [ON]\n");
                    else if (eq(hook, ORIGINAL, 4)) s.append("   [off]\n");
                    else s.append("   [unknown]\n");

                    String perf = readOneLine("/proc/sys/kernel/perf_event_paranoid");
                    s.append("perf      : ").append(perf == null ? "n/a" : perf).append("\n");
                    s.append("stage1    : .glp0 ").append(exists(D + "/.glp0") ? "seen" : "-").append("\n");
                    s.append("stage2    : .glp2 ").append(exists(D + "/.glp2") ? "seen" : "-").append("\n");

                    long ovl = countIn("/proc/mounts", "upperdir=" + D + "/glrt/gms");
                    s.append("GMS       : overlay ").append(ovl < 0 ? "n/a" : (ovl + "/3")).append("\n");

                    StringBuilder fs = new StringBuilder();
                    for (String n : SYNC_ASSETS) {
                        long dev = sizeOf(D + "/" + n);
                        long as = assetSize(n);
                        fs.append(n).append("=").append(dev < 0 ? "MISSING" : String.valueOf(dev));
                        if (dev >= 0 && as >= 0 && dev != as) fs.append("(asset ").append(as).append("!)");
                        fs.append("  ");
                    }
                    s.append("files     : ").append(fs).append("\n");

                    String log = readFile(D + "/glroot.log", 4);
                    s.append("--- glroot.log (head) ---\n").append(log);
                    s.append("restore   : ").append(ovl >= 3 ? "GMS OK (overlay mounted)" : (ovl < 0 ? "unknown" : "-")).append("\n");
                } catch (Throwable t) {
                    s.append("status error: ").append(t);
                }
                setStatus(s.toString());
                log("status refreshed");
            }
        });
    }

    private void armHook() {
        bg("arm", new Runnable() {
            public void run() {
                try {
                    byte[] dev = readDevicePayload();
                    if (dev == null || dev.length < 16) {
                        log("ERROR: " + D + "/" + PAYLOAD + " is missing - sync/push the payload first");
                        return;
                    }
                    byte[] nb = new byte[16];
                    System.arraycopy(dev, 0, nb, 0, 16);
                    final long ph = dev.length - 4;

                    File ih = extract("inject_hook", true);
                    log("inject_hook -> " + ih + "  (" + ih.length() + " bytes)");
                    log(String.format("device payload=%d bytes -> ph=0x%x", dev.length, ph));

                    byte[] hook = libc(OFF_HOOK, 4);
                    byte[] cave = libc(OFF_CAVE, 16);
                    if (eq(hook, HOOKED, 4) && eq(cave, nb, 16)) {
                        log("hook is ALREADY applied and the payload is in place - nothing to do");
                        return;
                    }
                    if (eq(hook, HOOKED, 4) && !eq(cave, nb, 16)) {
                        log("WARNING: a hook is applied but the payload bytes differ from this APK's asset");
                    }

                    // Up to 3 attempts: the Mali write lands only ~3/5 of the time (9an(157)D).
                    for (int i = 1; i <= 3; i++) {
                        log("attempt " + i + ": place + hook");
                        String out = exec(new String[] { ih.getAbsolutePath(), "place", "0x84000", "0x" + Long.toHexString(ph), "0x7a3d8" }, getFilesDir(), 20000);
                        log(out.trim());
                        out = exec(new String[] { ih.getAbsolutePath(), "hook", "0x7a3d4", "0x84000" }, getFilesDir(), 20000);
                        log(out.trim());
                        if (eq(libc(OFF_HOOK, 4), HOOKED, 4) && eq(libc(OFF_CAVE, 16), nb, 16)) {
                            log("VERIFIED: hook is live (libc@0x7a3d4 == 0b270014)");
                            break;
                        }
                        log("not landed yet (verification failed)");
                    }
                    byte[] h2 = libc(OFF_HOOK, 4);
                    log(eq(h2, HOOKED, 4)
                        ? "READY: now open Developer options and tap Take bug report"
                        : "FAILED to arm. Do NOT run restore. Reboot and try again.");
                } catch (Throwable t) {
                    log("armHook error: " + t);
                }
                refreshStatus();
            }
        });
    }

    private void syncFiles() {
        bg("sync", new Runnable() {
            public void run() {
                for (String n : SYNC_ASSETS) {
                    File dev = new File(D, n);
                    if (!dev.exists()) { log(n + ": not on the device - one time adb push needed"); continue; }
                    try {
                        InputStream in = getAssets().open(n);
                        byte[] ab = new byte[in.available()];
                        int rd = 0, n2;
                        while (rd < ab.length && (n2 = in.read(ab, rd, ab.length - rd)) > 0) rd += n2;
                        in.close();
                        if (ab.length != dev.length()) {
                            log(n + ": size differs (device " + dev.length() + " != asset " + ab.length + ") - cannot overwrite in place; adb push it");
                            continue;
                        }
                        RandomAccessFile f = new RandomAccessFile(dev, "rw");  // no truncate/create
                        f.seek(0);
                        f.write(ab);
                        f.close();
                        log(n + ": synced (" + ab.length + " bytes)");
                    } catch (Throwable t) {
                        log(n + ": sync failed: " + t);
                    }
                }
                log("sync done");
            }
        });
    }

    private void showLog() {
        bg("showlog", new Runnable() {
            public void run() {
                log("--- /data/local/tmp/glroot.log ---");
                post(readFile(D + "/glroot.log", 60));
                log("--- /data/local/tmp/gl.root.out (tail) ---");
                String o = readFile(D + "/gl.root.out", 200);
                String[] lines = o.split("\n");
                int from = Math.max(0, lines.length - 12);
                StringBuilder sb = new StringBuilder();
                for (int i = from; i < lines.length; i++) sb.append(lines[i]).append('\n');
                post(sb.toString());
            }
        });
    }

    /** ONESHOT: sync+arm, open Developer options for the single tap, then poll the result. */
    private void oneShotRestore() {
        bg("restore", new Runnable() { public void run() {
            try {
                log("=== ONESHOT RESTORE ===");
                for (String n : SYNC_ASSETS) {
                    File dev = new File(D, n);
                    if (!dev.exists()) { log("sync " + n + ": missing on device (one-time adb push needed)"); continue; }
                    try {
                        byte[] ab = assetBytes(n);
                        if (ab == null) { log("sync " + n + ": no asset"); continue; }
                        if (ab.length != dev.length()) { log("sync " + n + ": device " + dev.length() + " != asset " + ab.length + " - skipped (cannot resize in place)"); continue; }
                        RandomAccessFile f = new RandomAccessFile(dev, "rw"); f.seek(0); f.write(ab); f.close();
                        log("sync " + n + ": ok (" + ab.length + " B)");
                    } catch (Throwable t) { log("sync " + n + ": " + t); }
                }
                byte[] dev = readDevicePayload();
                if (dev == null || dev.length < 16) { log("ERROR: " + D + "/" + PAYLOAD + " missing"); return; }
                byte[] nb = new byte[16]; System.arraycopy(dev, 0, nb, 0, 16);
                long ph = dev.length - 4;
                File ih = extract("inject_hook", true);
                if (eq(libc(OFF_HOOK, 4), HOOKED, 4) && eq(libc(OFF_CAVE, 16), nb, 16)) {
                    log("hook already live - skipping arm");
                } else {
                    boolean ok = false;
                    for (int i = 1; i <= 3 && !ok; i++) {
                        log("arm attempt " + i + " (ph=0x" + Long.toHexString(ph) + ")");
                        log(exec(new String[] { ih.getAbsolutePath(), "place", "0x84000", "0x" + Long.toHexString(ph), "0x7a3d8" }, getFilesDir(), 20000).trim());
                        log(exec(new String[] { ih.getAbsolutePath(), "hook", "0x7a3d4", "0x84000" }, getFilesDir(), 20000).trim());
                        ok = eq(libc(OFF_HOOK, 4), HOOKED, 4) && eq(libc(OFF_CAVE, 16), nb, 16);
                        log(ok ? "VERIFIED hook live (libc@0x7a3d4 == 0b270014)" : "not landed yet");
                    }
                    if (!ok) { log("ARM FAILED. Reboot and try again; do NOT keep arming in one boot."); refreshStatus(); return; }
                }
                if (!requestBugreportAsOwner()) {
                    openDevOptions();
                    log(isA11yEnabled()
                        ? ">> a11y ON: 'Take bug report' は自動タップされます（0タップ）"
                        : ">> TAP \"Take bug report\" / 「バグレポートを取得」 ONCE（Device Owner か a11y を有効化すれば不要）");
                }
                boolean done = false;
                for (int s = 0; s < 180 && !done; s += 5) {
                    try { Thread.sleep(5000); } catch (InterruptedException e) { return; }
                    String perf = readOneLine("/proc/sys/kernel/perf_event_paranoid");
                    long ovl = countIn("/proc/mounts", "upperdir=" + D + "/glrt/gms");
                    log("t+" + s + "s perf=" + perf + " gms=" + (ovl < 0 ? "?" : ovl + "/3"));
                    if ("-1".equals(perf) && ovl >= 3) done = true;
                }
                log(done ? "RESTORE OK (perf=-1, GMS overlay 3/3)" : "not confirmed after 180s - press 状態を更新");
            } catch (Throwable t) { log("oneshot error: " + t); }
            refreshStatus();
        }});
    }

    /** Lower-bound measurement: can the app TRIGGER the restore by itself (0 taps)?
     *  It arms (same steps as the oneshot) then execs /system/bin/bugreportz and watches
     *  perf; if perf goes -1 the app alone is enough (0 taps), else 1 Settings tap. */
    private void probeAppTrigger() {
        bg("probe", new Runnable() { public void run() {
            try {
                byte[] dev = readDevicePayload();
                if (dev == null || dev.length < 16) { log("ERROR: " + D + "/" + PAYLOAD + " missing"); return; }
                byte[] nb = new byte[16]; System.arraycopy(dev, 0, nb, 0, 16);
                long ph = dev.length - 4;
                File ih = extract("inject_hook", true);
                if (!(eq(libc(OFF_HOOK, 4), HOOKED, 4) && eq(libc(OFF_CAVE, 16), nb, 16))) {
                    for (int i = 1; i <= 3; i++) {
                        log("probe arm attempt " + i);
                        log(exec(new String[] { ih.getAbsolutePath(), "place", "0x84000", "0x" + Long.toHexString(ph), "0x7a3d8" }, getFilesDir(), 20000).trim());
                        log(exec(new String[] { ih.getAbsolutePath(), "hook", "0x7a3d4", "0x84000" }, getFilesDir(), 20000).trim());
                        if (eq(libc(OFF_HOOK, 4), HOOKED, 4) && eq(libc(OFF_CAVE, 16), nb, 16)) break;
                    }
                }
                log("probe: hook=" + (eq(libc(OFF_HOOK, 4), HOOKED, 4) ? "ON" : "off"));
                String before = readOneLine("/proc/sys/kernel/perf_event_paranoid");
                log("probe: perf before = " + before + " ; exec /system/bin/bugreportz as the app");
                log(exec(new String[] { "/system/bin/bugreportz" }, null, 8000).trim());
                for (int i = 0; i < 10; i++) {
                    try { Thread.sleep(2000); } catch (InterruptedException e) { return; }
                    String p = readOneLine("/proc/sys/kernel/perf_event_paranoid");
                    log("probe t+" + ((i + 1) * 2) + "s perf=" + p);
                    if ("-1".equals(p)) { log(">>> 0-TAP TRIGGER WORKS (app exec'd bugreportz)"); return; }
                }
                log(">>> app-domain bugreportz did NOT set perf => needs the shell domain; 1 (Settings) tap is the ceiling");
            } catch (Throwable t) { log("probe error: " + t); }
        }});
    }

    private boolean isA11yEnabled() {
        try {
            String s = android.provider.Settings.Secure.getString(
                getContentResolver(), android.provider.Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES);
            return s != null && s.contains(getPackageName() + "/" + AutoTapService.class.getName());
        } catch (Throwable t) { return false; }
    }

    private void openA11ySettings() {
        try {
            startActivity(new Intent(android.provider.Settings.ACTION_ACCESSIBILITY_SETTINGS));
            log("a11y設定を開きました。一覧の 'GhostLock auto-tap' を有効にすると、以後は0タップになります（1回だけ）。");
        } catch (Throwable t) { log("a11y設定を開けません: " + t); }
    }

    private void checkA11y() {
        log("a11y auto-tap enabled = " + isA11yEnabled());
    }

    /** Device Owner?  If yes the app can trigger the bug report itself via
     *  DevicePolicyManager.requestBugreport() - no Settings tap, no accessibility. */
    private boolean isDeviceOwner() {
        try {
            android.app.admin.DevicePolicyManager dpm =
                (android.app.admin.DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
            return dpm != null && dpm.isDeviceOwnerApp(getPackageName());
        } catch (Throwable t) { return false; }
    }

    /** Trigger the same bugreportz/dumpstate flow programmatically (Device Owner only). */
    private boolean requestBugreportAsOwner() {
        try {
            android.app.admin.DevicePolicyManager dpm =
                (android.app.admin.DevicePolicyManager) getSystemService(DEVICE_POLICY_SERVICE);
            if (dpm == null || !dpm.isDeviceOwnerApp(getPackageName())) return false;
            android.content.ComponentName admin = new android.content.ComponentName(this, GhostAdminReceiver.class);
            dpm.requestBugreport(admin);
            log("DeviceOwner: requestBugreport() を発行しました（UIタップ不要）");
            return true;
        } catch (Throwable t) { log("requestBugreport failed: " + t); return false; }
    }

    private void openDevOptions() {
        try {
            startActivity(new Intent("android.settings.APPLICATION_DEVELOPMENT_SETTINGS"));
            log("opened Developer options - tap \"Take bug report\" / 「バグレポートを取得」 and confirm");
            log("the restore runs in the system's own bugreportz(uid 2000/shell) + dumpstate(uid 0)");
        } catch (Throwable t) {
            try {
                startActivity(new Intent(android.provider.Settings.ACTION_SETTINGS));
                log("opened Settings (fallback): go to System > Developer options > Take bug report");
            } catch (Throwable t2) {
                log("could not open Settings: " + t2);
            }
        }
    }
}
