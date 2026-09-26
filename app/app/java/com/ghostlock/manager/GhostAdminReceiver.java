package com.ghostlock.manager;

import android.app.admin.DeviceAdminReceiver;

/**
 * Device-owner receiver.  When the app is set as Device Owner (one-time
 * `adb shell dpm set-device-owner com.ghostlock.manager/.GhostAdminReceiver`), it can call
 * DevicePolicyManager.requestBugreport() to start the SAME dumpstate/bugreportz flow the
 * Settings "Take bug report" tap starts - with NO user tap and NO accessibility service.
 * It also becomes able to install APKs without the user prompt.
 */
public class GhostAdminReceiver extends DeviceAdminReceiver {
}
