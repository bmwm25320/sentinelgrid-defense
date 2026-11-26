package com.sentinelgrid.defense;

import android.app.AppOpsManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Process;
import android.provider.Settings;

/**
 * Restores armed SentinelGrid Android guards (Biometric App Lock and Background Gemini Co-Pilot)
 * permanently after device reboot.
 */
public class BootCompletedReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null || intent.getAction() == null) return;
        String action = intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action) && !"android.intent.action.QUICKBOOT_POWERON".equals(action)) {
            return;
        }

        SharedPreferences prefs = context.getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE);

        boolean lockEnabled = prefs.getBoolean(AppLockService.KEY_LOCK_ENABLED, false);
        String lockedCsv = prefs.getString(AppLockService.KEY_LOCKED_APPS, "");
        if (lockEnabled && !lockedCsv.trim().isEmpty() && hasUsageStatsPermission(context)) {
            Intent lockIntent = new Intent(context, AppLockService.class);
            startFg(context, lockIntent);
        }

        boolean geminiEnabled = prefs.getBoolean(GeminiOverlayService.KEY_GEMINI_BG_ENABLED, false);
        boolean canOverlay = Build.VERSION.SDK_INT < Build.VERSION_CODES.M || Settings.canDrawOverlays(context);
        if (geminiEnabled && canOverlay) {
            Intent gemIntent = new Intent(context, GeminiOverlayService.class);
            String savedKey = prefs.getString(GeminiOverlayService.KEY_GEMINI_API_KEY, "");
            gemIntent.putExtra(GeminiOverlayService.EXTRA_API_KEY, savedKey);
            startFg(context, gemIntent);
        }
    }

    private void startFg(Context context, Intent serviceIntent) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent);
            } else {
                context.startService(serviceIntent);
            }
        } catch (Exception ignored) {
        }
    }

    private boolean hasUsageStatsPermission(Context ctx) {
        try {
            AppOpsManager appOps = (AppOpsManager) ctx.getSystemService(Context.APP_OPS_SERVICE);
            if (appOps == null) return false;
            int mode = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                ? appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.getPackageName())
                : appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, Process.myUid(), ctx.getPackageName());
            return mode == AppOpsManager.MODE_ALLOWED;
        } catch (Exception e) {
            return false;
        }
    }
}
