package com.ghostlock.manager;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

/**
 * Talks to the GhostLock uid-0 task.
 *
 * <p>Channel A (tried first): the abstract unix socket {@code "\0gl_su"} served by the
 * exploit's {@code su_server()}.  From {@code untrusted_app*} this connect() is denied by
 * SELinux (there is no {@code (allow untrusted_app* shell (unix_stream_socket (connectto)))}
 * in device_plat_sepolicy.cil), so it normally fails with EACCES and we fall through.
 *
 * <p>Channel B: a file mail-slot.  We keep the request in a fixed 4096-byte record so that
 * we never need truncate/append (both are denied to app domains on shell_data_file).  We
 * only ever open an <em>existing</em> file for read/write.
 */
public final class RootClient {
    private static final int REC = 4096;

    public interface Logger { void log(String s); }

    public static final class Reply {
        public final String channel;
        public final String text;
        Reply(String channel, String text) { this.channel = channel; this.text = text; }
    }

    private final Logger log;
    private final List<File> slots = new ArrayList<File>();
    private long seq = 0;

    public RootClient(Logger log, File externalFilesDir, File privateFilesDir) {
        this.log = log;
        // Priority order.  The root poller watches all of these.
        slots.add(new File("/data/local/tmp/gl_ipc"));            // shell_data_file (pre-created by root)
        if (externalFilesDir != null) slots.add(new File(externalFilesDir, "gl_ipc")); // /sdcard/Android/data/<pkg>/files
        if (privateFilesDir != null)  slots.add(new File(privateFilesDir, "gl_ipc"));  // /data/user/0/<pkg>/files
    }

    /** One-shot command. Returns null if no root server answered on any channel. */
    public Reply exec(String cmd) {
        Reply a = viaSocket(cmd);
        if (a != null) return a;
        for (File dir : slots) {
            Reply b = viaSlot(dir, cmd);
            if (b != null) return b;
        }
        return null;
    }

    public String describeSlots() {
        StringBuilder sb = new StringBuilder();
        for (File f : slots) {
            sb.append(f.getAbsolutePath());
            if (f.isDirectory()) sb.append("  [dir exists]");
            else if (f.exists()) sb.append("  [path exists]");
            else sb.append("  [missing]");
            sb.append('\n');
        }
        return sb.toString();
    }

    // ---- Channel A -------------------------------------------------------
    private Reply viaSocket(String cmd) {
        LocalSocket s = new LocalSocket();
        try {
            s.connect(new LocalSocketAddress("gl_su", LocalSocketAddress.Namespace.ABSTRACT));
            s.setSoTimeout(8000);
            OutputStream os = s.getOutputStream();
            os.write(cmd.getBytes("UTF-8"));
            os.flush();
            s.shutdownOutput();
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            InputStream in = s.getInputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) > 0) bo.write(b, 0, n);
            return new Reply("abstract socket gl_su", bo.toString("UTF-8"));
        } catch (IOException e) {
            log.log("channel A gl_su: " + e.getClass().getSimpleName() + ": " + e.getMessage()
                    + "  -> falling back to file mail-slot");
            return null;
        } finally {
            try { s.close(); } catch (IOException ignored) { }
        }
    }

    // ---- Channel B -------------------------------------------------------
    private Reply viaSlot(File dir, String cmd) {
        File req = new File(dir, "req");
        File res = new File(dir, "res");
        if (!dir.isDirectory()) dir.mkdirs();   // works for app-owned dirs; fails harmlessly on /data/local/tmp
        long my;
        synchronized (this) { my = ++seq; }
        final String hex = String.format("%016x", my);

        try {
            byte[] rec = new byte[REC];
            System.arraycopy("GLRQ".getBytes("UTF-8"), 0, rec, 0, 4);
            System.arraycopy(hex.getBytes("UTF-8"), 0, rec, 4, 16);
            byte[] cb = cmd.getBytes("UTF-8");
            int n = Math.min(cb.length, REC - 21);
            System.arraycopy(cb, 0, rec, 20, n);
            rec[20 + n] = 0;
            // RandomAccessFile "rw" => O_RDWR, i.e. NO O_TRUNC/O_APPEND (both denied).
            RandomAccessFile raf = new RandomAccessFile(req, "rw");
            try {
                raf.seek(0);
                raf.write(rec);
            } finally {
                raf.close();
            }
        } catch (IOException e) {
            log.log("slot " + dir + ": req write failed: " + e.getMessage());
            return null;
        }

        long deadline = System.currentTimeMillis() + 10000;
        while (System.currentTimeMillis() < deadline) {
            String body = readWhole(res);
            if (body != null) {
                int nl1 = body.indexOf('\n');
                if (nl1 > 5 && body.startsWith("GLRS ") && body.substring(5, nl1).equals(hex)) {
                    String parsed = parse(body, nl1);
                    if (parsed != null) return new Reply("mail-slot " + dir, parsed);
                }
            }
            try { Thread.sleep(100); } catch (InterruptedException ignored) { }
        }
        log.log("slot " + dir + ": timeout (no root poller answered)");
        return null;
    }

    private static String readWhole(File f) {
        if (!f.exists()) return null;
        long len = f.length();
        if (len <= 0 || len > 4L * 1024 * 1024) return null;
        try {
            byte[] b = new byte[(int) len];
            FileInputStream in = new FileInputStream(f);
            try {
                int off = 0, n;
                while (off < b.length && (n = in.read(b, off, b.length - off)) > 0) off += n;
            } finally {
                in.close();
            }
            return new String(b, "UTF-8");
        } catch (IOException e) {
            return null;
        }
    }

    private static String parse(String body, int nl1) {
        int nl2 = body.indexOf('\n', nl1 + 1);
        if (nl2 < 0) return null;
        String status = body.substring(nl1 + 1, nl2);
        int end = body.indexOf("__GL_END__", nl2 + 1);
        if (end < 0) return null;
        String out = body.substring(nl2 + 1, end);
        if (out.endsWith("\n")) out = out.substring(0, out.length() - 1);
        return "exit=" + status + "\n" + out;
    }
}
