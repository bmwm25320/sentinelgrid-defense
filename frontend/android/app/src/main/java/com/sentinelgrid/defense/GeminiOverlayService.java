package com.sentinelgrid.defense;

import android.app.ActivityManager;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.graphics.drawable.GradientDrawable;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Persistent Foreground Service providing an Always-On Floating Gemini Co-Pilot Bubble
 * across all Android apps (Chrome, WhatsApp, Banking, etc.) with interactive Task -> Options -> Execute flow.
 */
public class GeminiOverlayService extends Service {

    public static volatile boolean isRunning = false;
    public static final String EXTRA_API_KEY = "gemini_api_key";
    public static final String KEY_GEMINI_API_KEY = "gemini_saved_api_key";
    public static final String KEY_GEMINI_BG_ENABLED = "gemini_bg_enabled";
    private static final String CHANNEL_ID = "sentinelgrid_gemini_bg";
    private static final int NOTIFICATION_ID = 4820;

    private WindowManager windowManager;
    private View bubbleView;
    private View panelView;
    private WindowManager.LayoutParams bubbleParams;
    private WindowManager.LayoutParams panelParams;
    private String geminiApiKey = "";
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    public void onCreate() {
        super.onCreate();
        isRunning = true;
        createNotificationChannel();
        Notification notification = buildNotification();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
        windowManager = (WindowManager) getSystemService(WINDOW_SERVICE);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        SharedPreferences prefs = getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE);
        if (intent != null && intent.hasExtra(EXTRA_API_KEY)) {
            String key = intent.getStringExtra(EXTRA_API_KEY);
            if (key != null && !key.trim().isEmpty()) {
                geminiApiKey = key.trim();
                prefs.edit().putString(KEY_GEMINI_API_KEY, geminiApiKey).apply();
            }
        }
        if (TextUtils.isEmpty(geminiApiKey)) {
            geminiApiKey = prefs.getString(KEY_GEMINI_API_KEY, "");
        }
        if (Settings.canDrawOverlays(this) && bubbleView == null) {
            setupFloatingBubble();
        }
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        isRunning = false;
        removeViews();
        executor.shutdownNow();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID,
                "SentinelGrid Gemini Co-Pilot",
                NotificationManager.IMPORTANCE_LOW
            );
            channel.setDescription("Keeps Gemini AI Co-Pilot active across all Android apps.");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification() {
        Intent openIntent = new Intent(this, MainActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent pi = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
        );

        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
            ? new Notification.Builder(this, CHANNEL_ID)
            : new Notification.Builder(this);

        return builder
            .setContentTitle("SentinelGrid Gemini Co-Pilot Active")
            .setContentText("Running in background across apps · Tap floating orb for options")
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentIntent(pi)
            .setOngoing(true)
            .build();
    }

    private int dp(int val) {
        return Math.round(TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP, val, getResources().getDisplayMetrics()
        ));
    }

    private void removeViews() {
        if (windowManager != null) {
            try { if (bubbleView != null) windowManager.removeView(bubbleView); } catch (Exception ignored) {}
            try { if (panelView != null) windowManager.removeView(panelView); } catch (Exception ignored) {}
        }
        bubbleView = null;
        panelView = null;
    }

    private int overlayWindowType() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
            ? WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            : WindowManager.LayoutParams.TYPE_PHONE;
    }

    private void setupFloatingBubble() {
        TextView orb = new TextView(this);
        orb.setText("✦ AI");
        orb.setTextColor(Color.WHITE);
        orb.setTextSize(13f);
        orb.setGravity(Gravity.CENTER);
        orb.setPadding(dp(12), dp(10), dp(12), dp(10));

        GradientDrawable bg = new GradientDrawable();
        bg.setShape(GradientDrawable.OVAL);
        bg.setColor(Color.parseColor("#0EA5E9"));
        bg.setStroke(dp(2), Color.parseColor("#10B981"));
        orb.setBackground(bg);
        orb.setElevation(dp(8));

        bubbleParams = new WindowManager.LayoutParams(
            dp(54),
            dp(54),
            overlayWindowType(),
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        );
        bubbleParams.gravity = Gravity.TOP | Gravity.END;
        bubbleParams.x = dp(16);
        bubbleParams.y = dp(180);

        orb.setOnTouchListener(new View.OnTouchListener() {
            private int initX, initY;
            private float touchX, touchY;
            private long downTime;

            @Override
            public boolean onTouch(View v, MotionEvent event) {
                switch (event.getAction()) {
                    case MotionEvent.ACTION_DOWN:
                        initX = bubbleParams.x;
                        initY = bubbleParams.y;
                        touchX = event.getRawX();
                        touchY = event.getRawY();
                        downTime = System.currentTimeMillis();
                        return true;
                    case MotionEvent.ACTION_MOVE:
                        bubbleParams.x = initX - (int) (event.getRawX() - touchX);
                        bubbleParams.y = initY + (int) (event.getRawY() - touchY);
                        try { windowManager.updateViewLayout(bubbleView, bubbleParams); } catch (Exception ignored) {}
                        return true;
                    case MotionEvent.ACTION_UP:
                        if (System.currentTimeMillis() - downTime < 220 &&
                            Math.abs(event.getRawX() - touchX) < dp(8) &&
                            Math.abs(event.getRawY() - touchY) < dp(8)) {
                            toggleCommandPanel();
                        }
                        return true;
                }
                return false;
            }
        });

        bubbleView = orb;
        windowManager.addView(bubbleView, bubbleParams);
    }

    private void toggleCommandPanel() {
        if (panelView != null) {
            try { windowManager.removeView(panelView); } catch (Exception ignored) {}
            panelView = null;
            return;
        }
        showCommandPanel();
    }

    private void showCommandPanel() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(14), dp(14), dp(14), dp(14));

        GradientDrawable cardBg = new GradientDrawable();
        cardBg.setCornerRadius(dp(16));
        cardBg.setColor(Color.parseColor("#0B1120"));
        cardBg.setStroke(dp(1), Color.parseColor("#10B981"));
        root.setBackground(cardBg);

        // Header Row
        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);

        TextView title = new TextView(this);
        title.setText("✦ Gemini Co-Pilot (Background)");
        title.setTextColor(Color.WHITE);
        title.setTextSize(14f);
        title.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));
        header.addView(title);

        Button closeBtn = new Button(this);
        closeBtn.setText("Hide");
        closeBtn.setTextSize(11f);
        closeBtn.setOnClickListener(v -> toggleCommandPanel());
        header.addView(closeBtn);
        root.addView(header);

        // Task Input
        EditText input = new EditText(this);
        input.setHint("Ask Gemini a task (e.g. scan apps, check link, boost)...");
        input.setTextColor(Color.WHITE);
        input.setHintTextColor(Color.parseColor("#94A3B8"));
        input.setTextSize(13f);
        root.addView(input);

        LinearLayout resultsContainer = new LinearLayout(this);
        resultsContainer.setOrientation(LinearLayout.VERTICAL);

        TextView statusText = new TextView(this);
        statusText.setText("Enter a task and tap 'Get Options' — Gemini will suggest options and run whichever you choose.");
        statusText.setTextColor(Color.parseColor("#CBD5E1"));
        statusText.setTextSize(12f);
        statusText.setPadding(0, dp(6), 0, dp(6));

        ScrollView scroll = new ScrollView(this);
        LinearLayout innerScroll = new LinearLayout(this);
        innerScroll.setOrientation(LinearLayout.VERTICAL);
        innerScroll.addView(statusText);
        innerScroll.addView(resultsContainer);
        scroll.addView(innerScroll);

        LinearLayout.LayoutParams scrollLp = new LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, dp(220)
        );
        root.addView(scroll, scrollLp);

        // Actions Row
        LinearLayout btnRow = new LinearLayout(this);
        btnRow.setOrientation(LinearLayout.HORIZONTAL);

        Button askBtn = new Button(this);
        askBtn.setText("Get Options");
        askBtn.setBackgroundColor(Color.parseColor("#10B981"));
        askBtn.setTextColor(Color.BLACK);
        askBtn.setLayoutParams(new LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f));

        Button openAppBtn = new Button(this);
        openAppBtn.setText("Open Full App");
        openAppBtn.setOnClickListener(v -> {
            Intent i = new Intent(this, MainActivity.class);
            i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(i);
            toggleCommandPanel();
        });
        btnRow.addView(askBtn);
        btnRow.addView(openAppBtn);
        root.addView(btnRow);

        askBtn.setOnClickListener(v -> {
            String task = input.getText().toString().trim();
            if (TextUtils.isEmpty(task)) task = "Protect my phone and check security";
            final String finalTask = task;
            statusText.setText("Planning options for: \"" + finalTask + "\"...");
            resultsContainer.removeAllViews();

            executor.execute(() -> {
                SentinelDeviceGuardPlugin.AndroidTaskPlan plan = planWithOptionalGemini(finalTask);
                mainHandler.post(() -> {
                    statusText.setText(plan.analysis);
                    resultsContainer.removeAllViews();
                    for (SentinelDeviceGuardPlugin.AndroidTaskOption opt : plan.options) {
                        Button optBtn = new Button(this);
                        optBtn.setText("▶ " + opt.title + " — " + opt.description);
                        optBtn.setAllCaps(false);
                        optBtn.setTextSize(12f);
                        optBtn.setOnClickListener(ov -> executeAndroidOption(opt, statusText));
                        resultsContainer.addView(optBtn);
                    }
                });
            });
        });

        panelParams = new WindowManager.LayoutParams(
            dp(320),
            WindowManager.LayoutParams.WRAP_CONTENT,
            overlayWindowType(),
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT
        );
        panelParams.gravity = Gravity.CENTER;
        panelView = root;
        windowManager.addView(panelView, panelParams);
    }

    private SentinelDeviceGuardPlugin.AndroidTaskPlan planWithOptionalGemini(String task) {
        if (!TextUtils.isEmpty(geminiApiKey)) {
            String[] models = new String[]{"gemini-3.8-flash", "gemini-3-flash-preview"};
            for (String modelName : models) {
                try {
                    URL url = new URL("https://generativelanguage.googleapis.com/v1beta/models/" + modelName + ":generateContent?key=" + geminiApiKey);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setConnectTimeout(6000);
                conn.setReadTimeout(8000);
                conn.setDoOutput(true);

                String prompt = "You are SentinelGrid Android Background Co-Pilot. User task: \"" + task + "\". "
                    + "Return JSON ONLY: {\"analysis\":\"short explanation\",\"options\":[{\"id\":\"o1\",\"title\":\"short action\",\"description\":\"what it does\",\"actionType\":\"SCAN_APPS|CHECK_WIFI|CHECK_URL|BOOST_RAM|OPEN_APP\",\"param\":\"\"}]}";
                JSONObject reqBody = new JSONObject();
                JSONArray contents = new JSONArray();
                JSONObject c0 = new JSONObject();
                JSONArray parts = new JSONArray();
                parts.put(new JSONObject().put("text", prompt));
                c0.put("parts", parts);
                contents.put(c0);
                reqBody.put("contents", contents);
                reqBody.put("generationConfig", new JSONObject().put("responseMimeType", "application/json"));

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(reqBody.toString().getBytes("UTF-8"));
                }
                if (conn.getResponseCode() == 200) {
                    BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line);
                    JSONObject resp = new JSONObject(sb.toString());
                    String text = resp.getJSONArray("candidates").getJSONObject(0)
                        .getJSONObject("content").getJSONArray("parts").getJSONObject(0).getString("text");
                    JSONObject parsed = new JSONObject(text);
                    SentinelDeviceGuardPlugin.AndroidTaskPlan plan = new SentinelDeviceGuardPlugin.AndroidTaskPlan();
                    plan.analysis = parsed.optString("analysis", "Choose an action:");
                    JSONArray opts = parsed.optJSONArray("options");
                    if (opts != null && opts.length() > 0) {
                        for (int i = 0; i < opts.length(); i++) {
                            JSONObject o = opts.getJSONObject(i);
                            plan.options.add(new SentinelDeviceGuardPlugin.AndroidTaskOption(
                                o.optString("id", "opt_" + i),
                                o.optString("title", "Run Check"),
                                o.optString("description", ""),
                                o.optString("actionType", "OPEN_APP"),
                                o.optString("param", "")
                            ));
                        }
                        return plan;
                    }
                }
            } catch (Exception ignored) {
            }
            }
        }
        return SentinelDeviceGuardPlugin.planAndroidTaskOptions(task);
    }

    private void executeAndroidOption(SentinelDeviceGuardPlugin.AndroidTaskOption opt, TextView statusText) {
        if ("CHECK_URL".equals(opt.actionType)) {
            SentinelDeviceGuardPlugin.UrlRiskEvaluation eval = SentinelDeviceGuardPlugin.evaluateUrlSafety(opt.param);
            statusText.setText("Result (" + eval.domain + "): " + eval.status + " (Risk: " + eval.riskScore + "/100)");
            return;
        }
        if ("CHECK_CLIPBOARD".equals(opt.actionType)) {
            try {
                android.content.ClipboardManager cm = (android.content.ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                if (cm == null || !cm.hasPrimaryClip() || cm.getPrimaryClip() == null || cm.getPrimaryClip().getItemCount() == 0) {
                    statusText.setText("Clipboard is empty (Safe).");
                    return;
                }
                CharSequence cs = cm.getPrimaryClip().getItemAt(0).coerceToText(this);
                String text = cs != null ? cs.toString() : "";
                List<String> urls = SentinelDeviceGuardPlugin.extractUrlsFromText(text);
                int maxRisk = 0;
                String worstStatus = "SAFE";
                for (String u : urls) {
                    SentinelDeviceGuardPlugin.UrlRiskEvaluation eval = SentinelDeviceGuardPlugin.evaluateUrlSafety(u);
                    if (eval.riskScore > maxRisk) {
                        maxRisk = eval.riskScore;
                        worstStatus = eval.status;
                    }
                }
                statusText.setText("Clipboard Check: " + urls.size() + " URL(s) · Status: " + worstStatus + " (Risk: " + maxRisk + "/100)");
            } catch (Exception e) {
                statusText.setText("Clipboard check completed (protected OS access).");
            }
            return;
        }
        if ("SCAN_APPS".equals(opt.actionType)) {
            PackageManager pm = getPackageManager();
            List<PackageInfo> pkgs = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
            int userApps = 0;
            int highRisk = 0;
            int sideloaded = 0;
            for (PackageInfo p : pkgs) {
                if (p.applicationInfo == null || getPackageName().equals(p.packageName)) continue;
                boolean isSys = (p.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                if (isSys) continue;
                userApps++;
                String installer = null;
                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        installer = pm.getInstallSourceInfo(p.packageName).getInstallingPackageName();
                    }
                } catch (Exception ignored) {}
                boolean hasLauncher = pm.getLaunchIntentForPackage(p.packageName) != null;
                SentinelDeviceGuardPlugin.AppRiskEvaluation eval = SentinelDeviceGuardPlugin.evaluateAppRisk(
                    p.packageName, false, installer, hasLauncher, p.requestedPermissions
                );
                if (eval.isSideloaded) sideloaded++;
                if ("HIGH".equals(eval.riskLevel) || "CRITICAL".equals(eval.riskLevel)) highRisk++;
            }
            statusText.setText("APK Audit: " + userApps + " user apps · " + sideloaded + " sideloaded · " + highRisk + " high-risk detected.");
            return;
        }
        if ("CHECK_WIFI".equals(opt.actionType)) {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            Network active = cm != null ? cm.getActiveNetwork() : null;
            NetworkCapabilities caps = active != null ? cm.getNetworkCapabilities(active) : null;
            LinkProperties lp = active != null ? cm.getLinkProperties(active) : null;
            boolean isVpn = caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
            boolean isCaptive = caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL);
            boolean privDns = lp != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && lp.isPrivateDnsActive();
            String transport = (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) ? "Wi-Fi" : "Cellular/Other";
            statusText.setText("Network (" + transport + "): " + (isCaptive ? "WARNING Captive Portal" : "Safe")
                + " · VPN: " + (isVpn ? "ON" : "OFF") + " · Private DNS: " + (privDns ? "ON" : "OFF"));
            return;
        }
        if ("BOOST_RAM".equals(opt.actionType)) {
            ActivityManager am = (ActivityManager) getSystemService(Context.ACTIVITY_SERVICE);
            PackageManager pm = getPackageManager();
            if (am != null) {
                ActivityManager.MemoryInfo beforeMem = new ActivityManager.MemoryInfo();
                am.getMemoryInfo(beforeMem);
                int killed = 0;
                for (ApplicationInfo app : pm.getInstalledApplications(0)) {
                    boolean isSys = (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                    if (SentinelDeviceGuardPlugin.isEligibleBackgroundAppForBoost(app.packageName, getPackageName(), isSys)) {
                        try { am.killBackgroundProcesses(app.packageName); killed++; } catch (Exception ignored) {}
                    }
                }
                ActivityManager.MemoryInfo afterMem = new ActivityManager.MemoryInfo();
                am.getMemoryInfo(afterMem);
                long freedMb = Math.max(0, (afterMem.availMem - beforeMem.availMem) / (1024 * 1024));
                statusText.setText("RAM Boost Complete: Cleared " + killed + " background apps · Freed " + freedMb + " MB RAM.");
                return;
            }
        }
        Intent i = new Intent(this, MainActivity.class);
        i.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
        startActivity(i);
        toggleCommandPanel();
    }
}
