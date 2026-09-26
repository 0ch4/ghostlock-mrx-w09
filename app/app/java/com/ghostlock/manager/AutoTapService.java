package com.ghostlock.manager;

import android.accessibilityservice.AccessibilityService;
import android.util.Log;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

/**
 * One-job AccessibilityService: when the Developer-options screen is up, click the
 * "Take bug report" / 「バグレポートを取得」 item so the user does NOT have to tap it.
 *
 * The restore trigger is the system bug-report path (bugreportz uid-2000/shell + dumpstate
 * uid-0); the app cannot trigger it itself (measured: app-domain bugreportz does not set
 * perf).  This service only performs that ONE tap on the Settings screen, so after a
 * one-time enable every restore is zero-tap.
 */
public class AutoTapService extends AccessibilityService {
    private static final String TAG = "GhostLock";
    private static final String SETTINGS_PKG = "com.android.settings";
    private static final String[] NEEDLES = {
        "バグレポートを取得", "Take bug report",
        "完全レポート", "Full report",
        "報告"
    };
    private long lastClickMs = 0;

    @Override
    public void onAccessibilityEvent(AccessibilityEvent e) {
        if (e == null) return;
        int t = e.getEventType();
        if (t != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
                && t != AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED) return;
        CharSequence pkg = e.getPackageName();
        if (pkg == null || !SETTINGS_PKG.contentEquals(pkg)) return;

        AccessibilityNodeInfo root = getRootInActiveWindow();
        if (root == null) return;
        AccessibilityNodeInfo target = find(root, 0);
        if (target == null) return;

        long now = System.currentTimeMillis();
        if (now - lastClickMs < 3000) return;   // don't double-tap

        AccessibilityNodeInfo clickable = target;
        for (int i = 0; clickable != null && !clickable.isClickable() && i < 8; i++) clickable = clickable.getParent();
        if (clickable == null) clickable = target;
        try {
            if (clickable.performAction(AccessibilityNodeInfo.ACTION_CLICK)) {
                lastClickMs = now;
                CharSequence txt = clickable.getText();
                Log.i(TAG, "a11y: auto-clicked '" + (txt == null ? "?" : txt) + "'");
            }
        } catch (Throwable th) {
            Log.i(TAG, "a11y: click failed " + th);
        }
    }

    private AccessibilityNodeInfo find(AccessibilityNodeInfo n, int depth) {
        if (n == null || depth > 40) return null;
        CharSequence txt = n.getText();
        if (txt == null) txt = n.getContentDescription();
        if (txt != null) {
            String s = txt.toString();
            for (String nd : NEEDLES) if (s.contains(nd)) return n;
        }
        int c = n.getChildCount();
        for (int i = 0; i < c; i++) {
            AccessibilityNodeInfo r = find(n.getChild(i), depth + 1);
            if (r != null) return r;
        }
        return null;
    }

    @Override
    public void onInterrupt() { }
}
