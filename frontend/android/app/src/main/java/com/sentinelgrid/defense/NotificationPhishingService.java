package com.sentinelgrid.defense;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.service.notification.NotificationListenerService;
import android.service.notification.StatusBarNotification;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * Kaspersky-Grade Safe Messaging & Notification Phishing Shield:
 * Scans incoming SMS, WhatsApp, and Messenger notifications for dangerous links.
 */
public class NotificationPhishingService extends NotificationListenerService {

    public static volatile boolean isConnected = false;
    public static final String PREFS_NAME = "sentinelgrid_security_prefs";
    public static final String KEY_ALERTS = "phishing_alerts_json";
    private static final String CHANNEL_ID = "sentinelgrid_phishing_alerts";

    @Override
    public void onListenerConnected() {
        super.onListenerConnected();
        isConnected = true;
    }

    @Override
    public void onListenerDisconnected() {
        isConnected = false;
        super.onListenerDisconnected();
    }

    @Override
    public void onNotificationPosted(StatusBarNotification sbn) {
        if (sbn == null || getPackageName().equals(sbn.getPackageName())) return;
        Notification notif = sbn.getNotification();
        if (notif == null || notif.extras == null) return;

        Bundle extras = notif.extras;
        CharSequence titleSeq = extras.getCharSequence(Notification.EXTRA_TITLE);
        CharSequence textSeq = extras.getCharSequence(Notification.EXTRA_TEXT);
        CharSequence bigSeq = extras.getCharSequence(Notification.EXTRA_BIG_TEXT);

        String combined = (titleSeq != null ? titleSeq + " " : "")
            + (textSeq != null ? textSeq + " " : "")
            + (bigSeq != null ? bigSeq.toString() : "");

        List<String> urls = SentinelDeviceGuardPlugin.extractUrlsFromText(combined);
        for (String url : urls) {
            SentinelDeviceGuardPlugin.UrlRiskEvaluation eval = SentinelDeviceGuardPlugin.evaluateUrlSafety(url);
            if ("DANGEROUS".equals(eval.status) || "SUSPICIOUS".equals(eval.status)) {
                saveAlert(sbn.getPackageName(), url, eval);
                raiseWarningNotification(sbn.getPackageName(), eval);
            }
        }
    }

    private void saveAlert(String sourceApp, String url, SentinelDeviceGuardPlugin.UrlRiskEvaluation eval) {
        try {
            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            JSONArray arr = new JSONArray(prefs.getString(KEY_ALERTS, "[]"));
            JSONObject obj = new JSONObject();
            obj.put("sourceApp", sourceApp);
            obj.put("url", url);
            obj.put("status", eval.status);
            obj.put("riskScore", eval.riskScore);
            obj.put("timestamp", System.currentTimeMillis());
            JSONArray next = new JSONArray();
            next.put(obj);
            for (int i = 0; i < Math.min(arr.length(), 19); i++) {
                next.put(arr.get(i));
            }
            prefs.edit().putString(KEY_ALERTS, next.toString()).apply();
        } catch (Exception ignored) {
        }
    }

    private void raiseWarningNotification(String sourceApp, SentinelDeviceGuardPlugin.UrlRiskEvaluation eval) {
        try {
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm == null) return;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID,
                    "SentinelGrid Phishing Warnings",
                    NotificationManager.IMPORTANCE_HIGH
                );
                nm.createNotificationChannel(ch);
            }
            Notification.Builder b = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
            Notification warn = b
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("Phishing Link Detected (" + eval.status + ")")
                .setContentText("Do NOT tap link in " + sourceApp + ": " + eval.domain)
                .setAutoCancel(true)
                .build();
            nm.notify((int) (System.currentTimeMillis() % 100000), warn);
        } catch (Exception ignored) {
        }
    }
}
