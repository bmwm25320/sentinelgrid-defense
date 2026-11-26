package com.sentinelgrid.defense;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.app.usage.UsageEvents;
import android.app.usage.UsageStats;
import android.app.usage.UsageStatsManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Monitors foreground app launches and triggers AppLockActivity (Biometric / PIN)
 * whenever the user opens a protected Banking, Messaging, or Gallery app.
 */
public class AppLockService extends Service {

    public static volatile boolean isRunning = false;
    public static final String KEY_LOCKED_APPS = "locked_packages_csv";
    public static final String KEY_LOCK_PIN = "applock_pin";
    public static final String KEY_LOCK_ENABLED = "applock_enabled";
    private static final String CHANNEL_ID = "sentinelgrid_applock";
    private static final int NOTIFICATION_ID = 4825;
    private static final long UNLOCK_GRACE_MS = 25_000L;

    private static final Map<String, Long> temporaryUnlocks = new HashMap<>();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private Runnable pollTask;

    public static void markTemporarilyUnlocked(String pkg) {
        if (pkg != null && !pkg.isEmpty()) {
            temporaryUnlocks.put(pkg, System.currentTimeMillis() + UNLOCK_GRACE_MS);
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        isRunning = true;
        createChannel();
        Notification notif = buildNotification();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notif);
        }
        startMonitorLoop();
    }

    @Override
    public void onDestroy() {
        isRunning = false;
        if (pollTask != null) handler.removeCallbacks(pollTask);
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                CHANNEL_ID,
                "SentinelGrid Biometric App Lock",
                NotificationManager.IMPORTANCE_LOW
            );
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    private Notification buildNotification() {
        Notification.Builder b = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
            ? new Notification.Builder(this, CHANNEL_ID)
            : new Notification.Builder(this);
        return b
            .setContentTitle("SentinelGrid Biometric App Lock Active")
            .setContentText("Guarding selected sensitive apps with Biometrics & PIN")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build();
    }

    private void startMonitorLoop() {
        pollTask = new Runnable() {
            @Override
            public void run() {
                checkForegroundApp();
                if (isRunning) {
                    handler.postDelayed(this, 900);
                }
            }
        };
        handler.post(pollTask);
    }

    private void checkForegroundApp() {
        SharedPreferences prefs = getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE);
        String csv = prefs.getString(KEY_LOCKED_APPS, "");
        if (csv.trim().isEmpty()) return;

        Set<String> locked = new HashSet<>();
        for (String p : csv.split(",")) {
            String trimmed = p.trim();
            if (!trimmed.isEmpty()) locked.add(trimmed);
        }

        String fgPkg = getTopPackageName();
        if (fgPkg == null || fgPkg.equals(getPackageName())) return;

        if (SentinelDeviceGuardPlugin.isAppLockTarget(fgPkg, locked, temporaryUnlocks, System.currentTimeMillis())) {
            Intent lockIntent = new Intent(this, AppLockActivity.class);
            lockIntent.putExtra(AppLockActivity.EXTRA_TARGET_PACKAGE, fgPkg);
            lockIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            startActivity(lockIntent);
        }
    }

    private String getTopPackageName() {
        try {
            UsageStatsManager usm = (UsageStatsManager) getSystemService(Context.USAGE_STATS_SERVICE);
            if (usm == null) return null;
            long now = System.currentTimeMillis();

            // Prefer live UsageEvents (works reliably on Android 10-15 app switches)
            UsageEvents events = usm.queryEvents(now - 6_000, now);
            String latestEventPkg = null;
            long latestTs = 0L;
            if (events != null) {
                UsageEvents.Event evt = new UsageEvents.Event();
                while (events.hasNextEvent()) {
                    events.getNextEvent(evt);
                    int type = evt.getEventType();
                    if (type == UsageEvents.Event.ACTIVITY_RESUMED || type == UsageEvents.Event.MOVE_TO_FOREGROUND) {
                        if (evt.getTimeStamp() >= latestTs) {
                            latestTs = evt.getTimeStamp();
                            latestEventPkg = evt.getPackageName();
                        }
                    }
                }
            }
            if (latestEventPkg != null) return latestEventPkg;

            List<UsageStats> stats = usm.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, now - 15_000, now);
            if (stats == null || stats.isEmpty()) return null;
            UsageStats recent = null;
            for (UsageStats us : stats) {
                if (recent == null || us.getLastTimeUsed() > recent.getLastTimeUsed()) {
                    recent = us;
                }
            }
            return recent != null ? recent.getPackageName() : null;
        } catch (Exception e) {
            return null;
        }
    }
}
