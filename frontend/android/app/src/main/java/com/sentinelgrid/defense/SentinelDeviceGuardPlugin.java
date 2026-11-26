package com.sentinelgrid.defense;

import android.Manifest;
import android.app.ActivityManager;
import android.app.AppOpsManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.media.AudioManager;
import android.media.Ringtone;
import android.media.RingtoneManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.os.Process;
import android.os.StatFs;
import android.provider.Settings;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.PermissionState;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;
import com.getcapacitor.annotation.Permission;
import com.getcapacitor.annotation.PermissionCallback;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@CapacitorPlugin(
    name = "SentinelDeviceGuard",
    permissions = {
        @Permission(
            strings = {
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
            },
            alias = "location"
        ),
        @Permission(
            strings = { "android.permission.POST_NOTIFICATIONS" },
            alias = "notifications"
        )
    }
)
public class SentinelDeviceGuardPlugin extends Plugin {

    private static final Set<String> TRUSTED_INSTALLERS = new HashSet<>(Arrays.asList(
        "com.android.vending",
        "com.sec.android.app.samsungapps",
        "com.samsung.android.app.omcagent",
        "com.samsung.android.app.updatecenter",
        "com.sec.android.preloadinstaller",
        "com.amazon.venezia",
        "com.huawei.appmarket"
    ));

    public static class AppRiskEvaluation {
        public int riskScore;
        public String riskLevel;
        public boolean isSideloaded;
        public boolean stalkerwareSuspect;
        public List<String> reasons = new ArrayList<>();
        public List<String> dangerousPermissions = new ArrayList<>();
    }

    public static AppRiskEvaluation evaluateAppRisk(
        String packageName,
        boolean isSystemApp,
        String installerPackage,
        boolean hasLauncherIntent,
        String[] requestedPermissions
    ) {
        AppRiskEvaluation eval = new AppRiskEvaluation();
        Set<String> perms = new HashSet<>();
        if (requestedPermissions != null) {
            Collections.addAll(perms, requestedPermissions);
        }

        boolean isOemPkg = packageName != null && (
            packageName.startsWith("com.samsung.") ||
            packageName.startsWith("com.sec.android.") ||
            packageName.startsWith("com.google.android.")
        );
        boolean hasTrustedInstaller = installerPackage != null && (
            TRUSTED_INSTALLERS.contains(installerPackage) ||
            (isOemPkg && "com.android.packageinstaller".equals(installerPackage))
        );
        eval.isSideloaded = !isSystemApp && !isOemPkg && !hasTrustedInstaller;

        if (eval.isSideloaded) {
            eval.riskScore += 30;
            eval.reasons.add("Installed from outside Google Play (sideloaded APK source)");
        }

        boolean hasSms = perms.contains("android.permission.READ_SMS") || perms.contains("android.permission.RECEIVE_SMS");
        boolean hasOverlay = perms.contains("android.permission.SYSTEM_ALERT_WINDOW");
        boolean hasMic = perms.contains("android.permission.RECORD_AUDIO");
        boolean hasCam = perms.contains("android.permission.CAMERA");
        boolean hasBgLoc = perms.contains("android.permission.ACCESS_BACKGROUND_LOCATION");
        boolean hasFineLoc = perms.contains("android.permission.ACCESS_FINE_LOCATION");
        boolean hasInstallPkgs = perms.contains("android.permission.REQUEST_INSTALL_PACKAGES");
        boolean hasAccessibility = perms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE");

        if (hasSms) eval.dangerousPermissions.add("SMS_ACCESS");
        if (hasOverlay) eval.dangerousPermissions.add("SCREEN_OVERLAY");
        if (hasMic) eval.dangerousPermissions.add("MICROPHONE");
        if (hasCam) eval.dangerousPermissions.add("CAMERA");
        if (hasBgLoc || hasFineLoc) eval.dangerousPermissions.add("LOCATION_TRACKING");
        if (hasInstallPkgs) eval.dangerousPermissions.add("APK_DROPPER");
        if (hasAccessibility) eval.dangerousPermissions.add("ACCESSIBILITY_CONTROL");

        // Banking Trojan combo: Overlay + SMS interception (flag HIGH only if untrusted/sideloaded)
        if (hasOverlay && hasSms && !isSystemApp && !hasTrustedInstaller && !isOemPkg) {
            eval.riskScore += 45;
            eval.reasons.add("Banking Trojan pattern: untrusted APK can draw overlays and intercept SMS OTPs");
        }

        // Hidden Stalkerware / Spyware heuristic: no launcher icon + sensitive surveillance permissions
        if (!isSystemApp && !hasLauncherIntent && (hasMic || hasCam || hasBgLoc || hasFineLoc || hasSms)) {
            eval.stalkerwareSuspect = true;
            eval.riskScore += 50;
            eval.reasons.add("Hidden background service without home-screen icon using camera/mic/location/SMS");
        }

        // Dropper heuristic: Sideloaded app that can silently prompt APK installs
        if (eval.isSideloaded && hasInstallPkgs) {
            eval.riskScore += 25;
            eval.reasons.add("Sideloaded app requests permission to install additional APK packages");
        }

        if (eval.riskScore > 100) eval.riskScore = 100;

        if (eval.riskScore >= 70) {
            eval.riskLevel = "CRITICAL";
        } else if (eval.riskScore >= 45) {
            eval.riskLevel = "HIGH";
        } else if (eval.riskScore >= 20) {
            eval.riskLevel = "MEDIUM";
        } else {
            eval.riskLevel = "SAFE";
        }

        return eval;
    }

    public static class UrlRiskEvaluation {
        public String url;
        public String domain;
        public String status;
        public int riskScore;
        public List<String> reasons = new ArrayList<>();
    }

    public static UrlRiskEvaluation evaluateUrlSafety(String rawUrl) {
        UrlRiskEvaluation eval = new UrlRiskEvaluation();
        String urlStr = rawUrl == null ? "" : rawUrl.trim();
        if (!urlStr.startsWith("http://") && !urlStr.startsWith("https://")) {
            urlStr = "https://" + urlStr;
        }

        String host = "";
        String path = "";
        try {
            URI uri = URI.create(urlStr);
            host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.US);
            path = uri.getPath() == null ? "" : uri.getPath().toLowerCase(Locale.US);
        } catch (Exception ignored) {
        }

        int risk = 0;
        if (host.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) {
            risk += 45;
            eval.reasons.add("URL uses raw IPv4 address instead of a verified domain.");
        }
        String[] riskyTlds = {".xyz", ".top", ".buzz", ".click", ".gq", ".cf", ".tk", ".ml", ".zip"};
        for (String tld : riskyTlds) {
            if (host.endsWith(tld)) {
                risk += 35;
                eval.reasons.add("High-abuse TLD detected (" + tld + ").");
                break;
            }
        }
        String[] dangerExts = {".apk", ".exe", ".scr", ".bat", ".ps1", ".msi"};
        for (String ext : dangerExts) {
            if (path.endsWith(ext)) {
                risk += 60;
                eval.reasons.add("Direct executable/APK payload download detected (" + ext + ").");
                break;
            }
        }
        if (urlStr.contains("@")) {
            risk += 45;
            eval.reasons.add("URL contains '@' redirection obfuscation.");
        }

        eval.url = urlStr;
        eval.domain = host;
        eval.riskScore = Math.min(100, risk);
        eval.status = risk >= 60 ? "DANGEROUS" : (risk >= 25 ? "SUSPICIOUS" : "SAFE");
        return eval;
    }

    @PluginMethod
    public void scanInstalledApps(PluginCall call) {
        Context ctx = getContext();
        PackageManager pm = ctx.getPackageManager();
        String selfPkg = ctx.getPackageName();

        List<PackageInfo> packages;
        try {
            packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS);
        } catch (Exception e) {
            call.reject("Failed to query installed packages: " + e.getMessage());
            return;
        }

        JSArray appsArray = new JSArray();
        int userAppsCount = 0;
        int sideloadedCount = 0;
        int highRiskCount = 0;
        int stalkerwareCount = 0;

        for (PackageInfo pkg : packages) {
            if (pkg.applicationInfo == null || selfPkg.equals(pkg.packageName)) {
                continue;
            }

            boolean isSystemApp = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
            boolean isUpdatedSystem = (pkg.applicationInfo.flags & ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0;
            if (isSystemApp && !isUpdatedSystem) {
                continue;
            }

            userAppsCount++;
            String installer = getInstallerPackage(pm, pkg.packageName);
            Intent launchIntent = pm.getLaunchIntentForPackage(pkg.packageName);
            boolean hasLauncher = launchIntent != null;

            AppRiskEvaluation eval = evaluateAppRisk(
                pkg.packageName,
                isSystemApp,
                installer,
                hasLauncher,
                pkg.requestedPermissions
            );

            if (eval.isSideloaded) sideloadedCount++;
            if ("HIGH".equals(eval.riskLevel) || "CRITICAL".equals(eval.riskLevel)) highRiskCount++;
            if (eval.stalkerwareSuspect) stalkerwareCount++;

            if (eval.riskScore >= 20 || appsArray.length() < 60) {
                JSObject appObj = new JSObject();
                CharSequence labelSeq = pm.getApplicationLabel(pkg.applicationInfo);
                appObj.put("appName", labelSeq != null ? labelSeq.toString() : pkg.packageName);
                appObj.put("packageName", pkg.packageName);
                appObj.put("versionName", pkg.versionName != null ? pkg.versionName : "1.0");
                appObj.put("installer", installer != null ? installer : "Unknown / Sideloaded");
                appObj.put("isSideloaded", eval.isSideloaded);
                appObj.put("stalkerwareSuspect", eval.stalkerwareSuspect);
                appObj.put("riskScore", eval.riskScore);
                appObj.put("riskLevel", eval.riskLevel);

                JSArray permsArr = new JSArray();
                for (String dp : eval.dangerousPermissions) permsArr.put(dp);
                appObj.put("dangerousPermissions", permsArr);

                JSArray reasonsArr = new JSArray();
                for (String r : eval.reasons) reasonsArr.put(r);
                appObj.put("reasons", reasonsArr);

                appsArray.put(appObj);
            }
        }

        int securityScore = Math.max(25, 100 - (highRiskCount * 15) - (stalkerwareCount * 20) - (sideloadedCount * 3));

        JSObject deviceInfo = new JSObject();
        deviceInfo.put("manufacturer", Build.MANUFACTURER);
        deviceInfo.put("model", Build.MODEL);
        deviceInfo.put("androidVersion", Build.VERSION.RELEASE);
        deviceInfo.put("sdkInt", Build.VERSION.SDK_INT);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            deviceInfo.put("securityPatch", Build.VERSION.SECURITY_PATCH);
        }

        JSObject res = new JSObject();
        res.put("totalPackagesChecked", packages.size());
        res.put("userAppsCount", userAppsCount);
        res.put("sideloadedCount", sideloadedCount);
        res.put("highRiskCount", highRiskCount);
        res.put("stalkerwareSuspects", stalkerwareCount);
        res.put("securityScore", securityScore);
        res.put("deviceInfo", deviceInfo);
        res.put("apps", appsArray);
        call.resolve(res);
    }

    private String getInstallerPackage(PackageManager pm, String packageName) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                InstallSourceInfo info = pm.getInstallSourceInfo(packageName);
                return info.getInstallingPackageName();
            } else {
                @SuppressWarnings("deprecation")
                String legacyInstaller = pm.getInstallerPackageName(packageName);
                return legacyInstaller;
            }
        } catch (Exception e) {
            return null;
        }
    }

    @PluginMethod
    public void inspectWifiSecurity(PluginCall call) {
        Context ctx = getContext();
        ConnectivityManager cm = (ConnectivityManager) ctx.getSystemService(Context.CONNECTIVITY_SERVICE);
        JSObject res = new JSObject();

        if (cm == null) {
            res.put("status", "UNKNOWN");
            res.put("transport", "NONE");
            call.resolve(res);
            return;
        }

        Network activeNetwork = cm.getActiveNetwork();
        NetworkCapabilities caps = activeNetwork != null ? cm.getNetworkCapabilities(activeNetwork) : null;
        LinkProperties linkProps = activeNetwork != null ? cm.getLinkProperties(activeNetwork) : null;

        boolean isWifi = caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI);
        boolean isCellular = caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR);
        boolean isVpn = caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        boolean isCaptivePortal = caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL);
        boolean privateDnsActive = false;
        if (linkProps != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            privateDnsActive = linkProps.isPrivateDnsActive();
        }

        String status = isCaptivePortal ? "WARNING" : "SAFE";
        res.put("status", status);
        res.put("transport", isWifi ? "WI-FI" : (isCellular ? "CELLULAR" : "OFFLINE"));
        res.put("vpnActive", isVpn);
        res.put("captivePortalDetected", isCaptivePortal);
        res.put("privateDnsActive", privateDnsActive);
        res.put("advice", isCaptivePortal
            ? "Public Captive Portal detected: avoid banking until VPN is enabled."
            : (isVpn ? "Encrypted VPN tunnel active." : "Active transport verified."));
        call.resolve(res);
    }

    @PluginMethod
    public void checkUrlSafety(PluginCall call) {
        String url = call.getString("url", "");
        UrlRiskEvaluation eval = evaluateUrlSafety(url);
        JSObject res = new JSObject();
        res.put("url", eval.url);
        res.put("domain", eval.domain);
        res.put("status", eval.status);
        res.put("risk_score", eval.riskScore);
        JSArray reasonsArr = new JSArray();
        for (String r : eval.reasons) reasonsArr.put(r);
        res.put("reasons", reasonsArr);
        call.resolve(res);
    }

    public static class AndroidTaskOption {
        public String id;
        public String title;
        public String description;
        public String actionType;
        public String param;

        public AndroidTaskOption(String id, String title, String description, String actionType, String param) {
            this.id = id;
            this.title = title;
            this.description = description;
            this.actionType = actionType;
            this.param = param;
        }
    }

    public static class AndroidTaskPlan {
        public String analysis;
        public List<AndroidTaskOption> options = new ArrayList<>();
    }

    public static AndroidTaskPlan planAndroidTaskOptions(String task) {
        AndroidTaskPlan plan = new AndroidTaskPlan();
        String q = task == null ? "" : task.toLowerCase(Locale.US);

        if (q.contains("http") || q.contains(".com") || q.contains(".apk") || q.contains("link") || q.contains("url")) {
            String candidate = "";
            for (String token : (task == null ? "" : task).split("\\s+")) {
                if (token.contains(".") || token.startsWith("http")) {
                    candidate = token;
                    break;
                }
            }
            plan.analysis = "I can verify link safety in the background before you open it. Pick an option:";
            plan.options.add(new AndroidTaskOption("opt_url", "Inspect Link Safety", "Checks phishing, raw IPs & APK drops", "CHECK_URL", candidate.isEmpty() ? "https://example.com" : candidate));
            plan.options.add(new AndroidTaskOption("opt_wifi", "Audit Active Wi-Fi Security", "Checks captive portal & Private DNS", "CHECK_WIFI", ""));
            return plan;
        }

        if (q.contains("wifi") || q.contains("network") || q.contains("vpn")) {
            plan.analysis = "Ready to inspect your current mobile network connection. Choose how to proceed:";
            plan.options.add(new AndroidTaskOption("opt_wifi", "Run Wi-Fi & DNS Audit", "Checks transport security & captive portal", "CHECK_WIFI", ""));
            plan.options.add(new AndroidTaskOption("opt_apps", "Scan Apps for Network Abuse", "Checks sideloaded APKs & stalkerware", "SCAN_APPS", ""));
            return plan;
        }

        if (q.contains("slow") || q.contains("ram") || q.contains("boost") || q.contains("clean") || q.contains("speed") || q.contains("battery")) {
            plan.analysis = "Ready to optimize Android memory and stop idle background apps. Choose an option:";
            plan.options.add(new AndroidTaskOption("opt_boost", "Boost RAM & Stop Bloat", "Clears background processes safely", "BOOST_RAM", ""));
            plan.options.add(new AndroidTaskOption("opt_scan", "Audit Installed APKs", "Checks sideloaded or draining apps", "SCAN_APPS", ""));
            return plan;
        }

        plan.analysis = "Gemini Background Co-Pilot is ready across apps. Select an action to execute:";
        plan.options.add(new AndroidTaskOption("opt_scan", "Scan Installed Apps & Stalkerware", "Audits sideloaded APKs & toxic permissions", "SCAN_APPS", ""));
        plan.options.add(new AndroidTaskOption("opt_boost", "Boost RAM & Clear Background Apps", "Frees phone memory safely", "BOOST_RAM", ""));
        plan.options.add(new AndroidTaskOption("opt_wifi", "Check Wi-Fi & DNS Security", "Inspects active connection safety", "CHECK_WIFI", ""));
        plan.options.add(new AndroidTaskOption("opt_open", "Open Full SentinelGrid Suite", "Launches Vault, Breach Audit & Shields", "OPEN_APP", ""));
        return plan;
    }

    @PluginMethod
    public void getOverlayStatus(PluginCall call) {
        Context ctx = getContext();
        boolean hasPerm = Build.VERSION.SDK_INT < Build.VERSION_CODES.M || Settings.canDrawOverlays(ctx);
        JSObject res = new JSObject();
        res.put("hasOverlayPermission", hasPerm);
        res.put("serviceRunning", GeminiOverlayService.isRunning);
        call.resolve(res);
    }

    @PluginMethod
    public void requestOverlayPermission(PluginCall call) {
        Context ctx = getContext();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(ctx)) {
            Intent intent = new Intent(
                Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                Uri.parse("package:" + ctx.getPackageName())
            );
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            ctx.startActivity(intent);
        }
        call.resolve();
    }

    @PluginMethod
    public void startBackgroundGemini(PluginCall call) {
        Context ctx = getContext();
        String apiKey = call.getString("apiKey", "");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(ctx)) {
            call.reject("OVERLAY_PERMISSION_REQUIRED");
            return;
        }
        SharedPreferences prefs = ctx.getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor ed = prefs.edit().putBoolean(GeminiOverlayService.KEY_GEMINI_BG_ENABLED, true);
        if (apiKey != null && !apiKey.trim().isEmpty()) {
            ed.putString(GeminiOverlayService.KEY_GEMINI_API_KEY, apiKey.trim());
        }
        ed.apply();

        Intent serviceIntent = new Intent(ctx, GeminiOverlayService.class);
        serviceIntent.putExtra(GeminiOverlayService.EXTRA_API_KEY, apiKey);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ctx.startForegroundService(serviceIntent);
        } else {
            ctx.startService(serviceIntent);
        }
        JSObject res = new JSObject();
        res.put("started", true);
        call.resolve(res);
    }

    @PluginMethod
    public void stopBackgroundGemini(PluginCall call) {
        Context ctx = getContext();
        ctx.getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(GeminiOverlayService.KEY_GEMINI_BG_ENABLED, false)
            .apply();
        ctx.stopService(new Intent(ctx, GeminiOverlayService.class));
        JSObject res = new JSObject();
        res.put("stopped", true);
        call.resolve(res);
    }

    public static boolean isEligibleBackgroundAppForBoost(String packageName, String selfPackageName, boolean isSystemApp) {
        if (packageName == null || packageName.isEmpty()) return false;
        if (packageName.equals(selfPackageName)) return false;
        if (isSystemApp) return false;
        if (packageName.startsWith("com.android.systemui") || packageName.startsWith("com.google.android.gms")) {
            return false;
        }
        return true;
    }

    @PluginMethod
    public void boostBackgroundMemory(PluginCall call) {
        Context ctx = getContext();
        ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
        PackageManager pm = ctx.getPackageManager();
        String selfPkg = ctx.getPackageName();

        if (am == null) {
            call.reject("ActivityManager unavailable");
            return;
        }

        ActivityManager.MemoryInfo beforeMem = new ActivityManager.MemoryInfo();
        am.getMemoryInfo(beforeMem);
        long availBeforeMb = beforeMem.availMem / (1024 * 1024);
        long totalMb = beforeMem.totalMem / (1024 * 1024);

        int killedCount = 0;
        try {
            List<ApplicationInfo> apps = pm.getInstalledApplications(0);
            for (ApplicationInfo app : apps) {
                boolean isSys = (app.flags & ApplicationInfo.FLAG_SYSTEM) != 0;
                if (isEligibleBackgroundAppForBoost(app.packageName, selfPkg, isSys)) {
                    try {
                        am.killBackgroundProcesses(app.packageName);
                        killedCount++;
                    } catch (Exception ignored) {
                    }
                }
            }
        } catch (Exception ignored) {
        }

        ActivityManager.MemoryInfo afterMem = new ActivityManager.MemoryInfo();
        am.getMemoryInfo(afterMem);
        long availAfterMb = afterMem.availMem / (1024 * 1024);
        long freedMb = Math.max(0, availAfterMb - availBeforeMb);

        JSObject res = new JSObject();
        res.put("killedPackagesCount", killedCount);
        res.put("availableBeforeMb", availBeforeMb);
        res.put("availableAfterMb", availAfterMb);
        res.put("freedMb", freedMb);
        res.put("totalMemoryMb", totalMb);
        call.resolve(res);
    }

    // ==================== SAFE MESSAGING URL EXTRACTOR & PHISHING SHIELD ====================

    private static final Pattern URL_PATTERN = Pattern.compile(
        "(https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+)",
        Pattern.CASE_INSENSITIVE
    );

    private static Ringtone activeAlarmRingtone = null;

    public static List<String> extractUrlsFromText(String text) {
        List<String> urls = new ArrayList<>();
        if (text == null || text.isEmpty()) return urls;
        Matcher m = URL_PATTERN.matcher(text);
        while (m.find()) {
            urls.add(m.group(1));
        }
        return urls;
    }

    public static boolean isAppLockTarget(
        String pkg,
        Set<String> lockedPackages,
        Map<String, Long> temporaryUnlocks,
        long nowMs
    ) {
        if (pkg == null || lockedPackages == null || !lockedPackages.contains(pkg)) return false;
        if (temporaryUnlocks != null && temporaryUnlocks.containsKey(pkg)) {
            Long expires = temporaryUnlocks.get(pkg);
            if (expires != null && expires > nowMs) return false;
        }
        return true;
    }

    @PluginMethod
    public void getNotificationShieldStatus(PluginCall call) {
        Context ctx = getContext();
        String enabledListeners = Settings.Secure.getString(
            ctx.getContentResolver(),
            "enabled_notification_listeners"
        );
        ComponentName cn = new ComponentName(ctx, NotificationPhishingService.class);
        boolean permGranted = enabledListeners != null && enabledListeners.contains(cn.flattenToString());

        SharedPreferences prefs = ctx.getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE);
        JSArray alertsArr;
        try {
            alertsArr = new JSArray(prefs.getString(NotificationPhishingService.KEY_ALERTS, "[]"));
        } catch (Exception e) {
            alertsArr = new JSArray();
        }

        JSObject res = new JSObject();
        res.put("permissionGranted", permGranted);
        res.put("serviceConnected", NotificationPhishingService.isConnected);
        res.put("alerts", alertsArr);
        call.resolve(res);
    }

    @PluginMethod
    public void requestNotificationAccess(PluginCall call) {
        Intent i = new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        getContext().startActivity(i);
        call.resolve();
    }

    @PluginMethod
    public void clearPhishingAlerts(PluginCall call) {
        SharedPreferences prefs = getContext().getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(NotificationPhishingService.KEY_ALERTS, "[]").apply();
        call.resolve();
    }

    // ==================== BIOMETRIC APP LOCK ====================

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

    @PluginMethod
    public void getAppLockStatus(PluginCall call) {
        Context ctx = getContext();
        SharedPreferences prefs = ctx.getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE);
        String csv = prefs.getString(AppLockService.KEY_LOCKED_APPS, "");
        JSArray lockedArr = new JSArray();
        for (String p : csv.split(",")) {
            if (!p.trim().isEmpty()) lockedArr.put(p.trim());
        }
        JSObject res = new JSObject();
        res.put("hasUsageStatsPermission", hasUsageStatsPermission(ctx));
        res.put("serviceRunning", AppLockService.isRunning);
        res.put("lockedPackages", lockedArr);
        call.resolve(res);
    }

    @PluginMethod
    public void requestUsageStatsAccess(PluginCall call) {
        Intent i = new Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS);
        i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        getContext().startActivity(i);
        call.resolve();
    }

    @PluginMethod
    public void setAppLockConfig(PluginCall call) {
        Context ctx = getContext();
        JSArray pkgs = call.getArray("lockedPackages", new JSArray());
        String pin = call.getString("pin", "1234");
        boolean enabled = Boolean.TRUE.equals(call.getBoolean("enabled", true));

        List<String> list = new ArrayList<>();
        try {
            for (int i = 0; i < pkgs.length(); i++) {
                String val = pkgs.getString(i);
                if (val != null && !val.trim().isEmpty()) list.add(val.trim());
            }
        } catch (Exception ignored) {
        }

        SharedPreferences prefs = ctx.getSharedPreferences(NotificationPhishingService.PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit()
            .putString(AppLockService.KEY_LOCKED_APPS, String.join(",", list))
            .putString(AppLockService.KEY_LOCK_PIN, pin != null && !pin.isEmpty() ? pin : "1234")
            .putBoolean(AppLockService.KEY_LOCK_ENABLED, enabled)
            .apply();

        Intent serviceIntent = new Intent(ctx, AppLockService.class);
        if (enabled && hasUsageStatsPermission(ctx)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ctx.startForegroundService(serviceIntent);
            } else {
                ctx.startService(serviceIntent);
            }
        } else if (!enabled) {
            ctx.stopService(serviceIntent);
        }

        JSObject res = new JSObject();
        res.put("savedCount", list.size());
        res.put("serviceRunning", enabled && hasUsageStatsPermission(ctx));
        call.resolve(res);
    }

    // ==================== ANTI-THEFT SIREN ALARM & LAST LOCATION ====================

    @PluginMethod
    public void triggerAntiTheftAlarm(PluginCall call) {
        Context ctx = getContext();
        try {
            AudioManager am = (AudioManager) ctx.getSystemService(Context.AUDIO_SERVICE);
            if (am != null) {
                int maxVol = am.getStreamMaxVolume(AudioManager.STREAM_ALARM);
                am.setStreamVolume(AudioManager.STREAM_ALARM, maxVol, 0);
            }
            Uri alarmUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM);
            if (alarmUri == null) alarmUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE);
            if (activeAlarmRingtone != null && activeAlarmRingtone.isPlaying()) {
                activeAlarmRingtone.stop();
            }
            activeAlarmRingtone = RingtoneManager.getRingtone(ctx, alarmUri);
            if (activeAlarmRingtone != null) {
                activeAlarmRingtone.play();
            }
            JSObject res = new JSObject();
            res.put("playing", true);
            call.resolve(res);
        } catch (Exception e) {
            call.reject("Could not trigger alarm: " + e.getMessage());
        }
    }

    @PluginMethod
    public void stopAntiTheftAlarm(PluginCall call) {
        try {
            if (activeAlarmRingtone != null && activeAlarmRingtone.isPlaying()) {
                activeAlarmRingtone.stop();
            }
            JSObject res = new JSObject();
            res.put("playing", false);
            call.resolve(res);
        } catch (Exception e) {
            call.resolve(new JSObject().put("playing", false));
        }
    }

    @PluginMethod
    public void getDeviceTelemetry(PluginCall call) {
        Context ctx = getContext();
        JSObject res = new JSObject();

        long totalMb = 4096;
        long availMb = 1536;
        try {
            ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
                am.getMemoryInfo(mi);
                totalMb = Math.max(512, mi.totalMem / (1024 * 1024));
                availMb = mi.availMem / (1024 * 1024);
            }
        } catch (Exception ignored) {}

        long usedMb = Math.max(0, totalMb - availMb);
        double ramPercent = Math.round((usedMb * 1000.0) / totalMb) / 10.0;

        double totalDiskGb = 64.0;
        double freeDiskGb = 32.0;
        try {
            StatFs stat = new StatFs(Environment.getDataDirectory().getPath());
            long blockSize = stat.getBlockSizeLong();
            long totalBlocks = stat.getBlockCountLong();
            long availBlocks = stat.getAvailableBlocksLong();
            totalDiskGb = Math.round((totalBlocks * blockSize) / (1024.0 * 1024.0 * 1024.0) * 10.0) / 10.0;
            freeDiskGb = Math.round((availBlocks * blockSize) / (1024.0 * 1024.0 * 1024.0) * 10.0) / 10.0;
        } catch (Exception ignored) {}

        int packageCount = 0;
        try {
            packageCount = ctx.getPackageManager().getInstalledApplications(0).size();
        } catch (Exception ignored) {}

        res.put("manufacturer", Build.MANUFACTURER);
        res.put("model", Build.MODEL);
        res.put("androidVersion", Build.VERSION.RELEASE);
        res.put("sdkInt", Build.VERSION.SDK_INT);
        res.put("cpuCores", Runtime.getRuntime().availableProcessors());
        res.put("memoryTotalMb", totalMb);
        res.put("memoryUsedMb", usedMb);
        res.put("memoryAvailMb", availMb);
        res.put("memoryPercent", ramPercent);
        res.put("diskTotalGb", totalDiskGb);
        res.put("diskFreeGb", freeDiskGb);
        res.put("installedPackagesCount", packageCount);
        call.resolve(res);
    }

    @PluginMethod
    public void getLastKnownLocation(PluginCall call) {
        if (getPermissionState("location") != PermissionState.GRANTED) {
            requestPermissionForAlias("location", call, "locationPermsCallback");
            return;
        }
        resolveLocationNow(call);
    }

    @PermissionCallback
    private void locationPermsCallback(PluginCall call) {
        if (getPermissionState("location") == PermissionState.GRANTED) {
            resolveLocationNow(call);
        } else {
            JSObject res = new JSObject();
            res.put("available", false);
            res.put("note", "Location permission denied. Grant Location permission in Android Settings for Anti-Theft GPS.");
            call.resolve(res);
        }
    }

    private void resolveLocationNow(PluginCall call) {
        Context ctx = getContext();
        try {
            LocationManager lm = (LocationManager) ctx.getSystemService(Context.LOCATION_SERVICE);
            if (lm == null) {
                call.resolve(new JSObject().put("available", false));
                return;
            }
            Location best = null;
            for (String provider : Arrays.asList(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER, LocationManager.PASSIVE_PROVIDER)) {
                try {
                    Location loc = lm.getLastKnownLocation(provider);
                    if (loc != null && (best == null || loc.getTime() > best.getTime())) {
                        best = loc;
                    }
                } catch (SecurityException ignored) {
                }
            }
            JSObject res = new JSObject();
            if (best != null) {
                res.put("available", true);
                res.put("latitude", best.getLatitude());
                res.put("longitude", best.getLongitude());
                res.put("accuracyMeters", best.getAccuracy());
            } else {
                res.put("available", false);
                res.put("note", "Location enabled, waiting for first GPS fix (turn on Device Location/GPS in Quick Settings).");
            }
            call.resolve(res);
        } catch (Exception e) {
            call.resolve(new JSObject().put("available", false));
        }
    }
}
