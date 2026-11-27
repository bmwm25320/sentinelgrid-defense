package com.sentinelgrid.defense;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Real-Time Android APK Install Guard:
 * Automatically audits every newly installed or updated package in real time
 * for untrusted sources, overlay + SMS trojan combinations, and hidden stalkerware.
 */
public class PackageInstallReceiver extends BroadcastReceiver {

    public static final String KEY_INSTALL_ALERTS = "install_scan_alerts_json";
    private static final String CHANNEL_ID = "sentinelgrid_install_guard";

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        String action = intent.getAction();
        if (!Intent.ACTION_PACKAGE_ADDED.equals(action) && !Intent.ACTION_PACKAGE_REPLACED.equals(action)) {
            return;
        }
        Uri data = intent.getData();
        if (data == null) return;
        String pkgName = data.getSchemeSpecificPart();
        if (pkgName == null || pkgName.isEmpty() || context.getPackageName().equals(pkgName)) {
            return;
        }

        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo pkg = pm.getPackageInfo(pkgName, PackageManager.GET_PERMISSIONS);
            if (pkg.applicationInfo == null) return;

            boolean isSystemApp = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            String installer = null;
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    InstallSourceInfo info = pm.getInstallSourceInfo(pkgName);
                    installer = info.getInstallingPackageName();
                } else {
                    @SuppressWarnings("deprecation")
                    String leg = pm.getInstallerPackageName(pkgName);
                    installer = leg;
                }
            } catch (Exception ignored) {
            }

            boolean hasLauncher = pm.getLaunchIntentForPackage(pkgName) != null;
            SentinelDeviceGuardPlugin.AppRiskEvaluation eval = SentinelDeviceGuardPlugin.evaluateAppRisk(
                pkgName, isSystemApp, installer, hasLauncher, pkg.requestedPermissions
            );
            CharSequence lbl = pm.getApplicationLabel(pkg.applicationInfo);
            String appLabel = lbl != null ? lbl.toString() : pkgName;

            if ("HIGH".equals(eval.riskLevel) || "CRITICAL".equals(eval.riskLevel) || eval.isSideloaded) {
                saveAlert(context, appLabel, pkgName, eval);
                postWarningNotification(context, appLabel, eval);
            }
        } catch (Exception ignored) {
        }
    }

    private void saveAlert(Context ctx, String appLabel, String pkgName, SentinelDeviceGuardPlugin.AppRiskEvaluation eval) {
        try {
            SharedPreferences prefs = ctx.getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE);
            JSONArray arr = new JSONArray(prefs.getString(KEY_INSTALL_ALERTS, "[]"));
            JSONObject obj = new JSONObject();
            obj.put("appName", appLabel);
            obj.put("packageName", pkgName);
            obj.put("riskLevel", eval.riskLevel);
            obj.put("riskScore", eval.riskScore);
            obj.put("timestamp", System.currentTimeMillis());
            JSONArray next = new JSONArray();
            next.put(obj);
            for (int i = 0; i < Math.min(arr.length(), 14); i++) {
                next.put(arr.get(i));
            }
            prefs.edit().putString(KEY_INSTALL_ALERTS, next.toString()).apply();
        } catch (Exception ignored) {
        }
    }

    private void postWarningNotification(Context ctx, String appLabel, SentinelDeviceGuardPlugin.AppRiskEvaluation eval) {
        try {
            NotificationManager nm = ctx.getSystemService(NotificationManager.class);
            if (nm == null) return;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID,
                    "SentinelGrid Real-Time Install Shield",
                    NotificationManager.IMPORTANCE_HIGH
                );
                nm.createNotificationChannel(ch);
            }
            Notification.Builder b = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(ctx, CHANNEL_ID)
                : new Notification.Builder(ctx);
            Notification notif = b
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("New App Scanned: " + eval.riskLevel + " Risk")
                .setContentText(appLabel + (eval.reasons.isEmpty() ? " requires security review." : " — " + eval.reasons.get(0)))
                .setAutoCancel(true)
                .build();
            nm.notify((int) (System.currentTimeMillis() % 90000) + 1000, notif);
        } catch (Exception ignored) {
        }
    }
}
