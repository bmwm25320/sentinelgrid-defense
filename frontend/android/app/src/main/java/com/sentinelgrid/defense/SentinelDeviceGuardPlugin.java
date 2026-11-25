package com.sentinelgrid.defense;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.InstallSourceInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@CapacitorPlugin(name = "SentinelDeviceGuard")
public class SentinelDeviceGuardPlugin extends Plugin {

    private static final Set<String> TRUSTED_INSTALLERS = new HashSet<>(Arrays.asList(
        "com.android.vending",
        "com.sec.android.app.samsungapps",
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

        boolean hasTrustedInstaller = installerPackage != null && TRUSTED_INSTALLERS.contains(installerPackage);
        eval.isSideloaded = !isSystemApp && !hasTrustedInstaller;

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

        // Banking Trojan combo: Overlay + SMS interception
        if (hasOverlay && hasSms && !isSystemApp) {
            eval.riskScore += 45;
            eval.reasons.add("Banking Trojan pattern: can draw screen overlays and read/intercept SMS OTPs");
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

        plan.analysis = "Gemini Background Co-Pilot is ready across apps. Select an action to execute:";
        plan.options.add(new AndroidTaskOption("opt_scan", "Scan Installed Apps & Stalkerware", "Audits sideloaded APKs & toxic permissions", "SCAN_APPS", ""));
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
        ctx.stopService(new Intent(ctx, GeminiOverlayService.class));
        JSObject res = new JSObject();
        res.put("stopped", true);
        call.resolve(res);
    }
}
