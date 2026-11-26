package com.sentinelgrid.defense;

import org.junit.Test;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.Assert.*;

public class SentinelDeviceGuardTest {

    @Test
    public void testPlayStoreBenignAppScoresSafe() {
        SentinelDeviceGuardPlugin.AppRiskEvaluation eval = SentinelDeviceGuardPlugin.evaluateAppRisk(
            "com.example.notes",
            false,
            "com.android.vending",
            true,
            new String[]{"android.permission.INTERNET"}
        );
        assertFalse(eval.isSideloaded);
        assertFalse(eval.stalkerwareSuspect);
        assertEquals("SAFE", eval.riskLevel);
        assertEquals(0, eval.riskScore);
    }

    @Test
    public void testSideloadedBankingTrojanScoresCritical() {
        SentinelDeviceGuardPlugin.AppRiskEvaluation eval = SentinelDeviceGuardPlugin.evaluateAppRisk(
            "com.fake.flashplayer",
            false,
            null,
            true,
            new String[]{
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECEIVE_SMS",
                "android.permission.REQUEST_INSTALL_PACKAGES"
            }
        );
        assertTrue(eval.isSideloaded);
        assertEquals("CRITICAL", eval.riskLevel);
        assertTrue(eval.riskScore >= 70);
        assertTrue(eval.dangerousPermissions.contains("SMS_ACCESS"));
        assertTrue(eval.dangerousPermissions.contains("SCREEN_OVERLAY"));
    }

    @Test
    public void testHiddenStalkerwareFlagged() {
        SentinelDeviceGuardPlugin.AppRiskEvaluation eval = SentinelDeviceGuardPlugin.evaluateAppRisk(
            "com.hidden.tracker",
            false,
            "com.android.packageinstaller",
            false,
            new String[]{
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION"
            }
        );
        assertTrue(eval.isSideloaded);
        assertTrue(eval.stalkerwareSuspect);
        assertEquals("CRITICAL", eval.riskLevel);
    }

    @Test
    public void testUrlSafetyAnalyzerDetectsMaliciousApkLink() {
        SentinelDeviceGuardPlugin.UrlRiskEvaluation dangerous =
            SentinelDeviceGuardPlugin.evaluateUrlSafety("http://192.168.1.55/update.apk");
        assertEquals("DANGEROUS", dangerous.status);
        assertTrue(dangerous.riskScore >= 60);

        SentinelDeviceGuardPlugin.UrlRiskEvaluation safe =
            SentinelDeviceGuardPlugin.evaluateUrlSafety("https://github.com");
        assertEquals("SAFE", safe.status);
        assertEquals(0, safe.riskScore);
    }

    @Test
    public void testAndroidGeminiTaskOptionsPlanner() {
        SentinelDeviceGuardPlugin.AndroidTaskPlan linkPlan =
            SentinelDeviceGuardPlugin.planAndroidTaskOptions("Check if http://evil.tk/app.apk is safe");
        assertNotNull(linkPlan.analysis);
        assertTrue(linkPlan.options.size() >= 2);
        assertEquals("CHECK_URL", linkPlan.options.get(0).actionType);

        SentinelDeviceGuardPlugin.AndroidTaskPlan generalPlan =
            SentinelDeviceGuardPlugin.planAndroidTaskOptions("Protect my Android device");
        assertTrue(generalPlan.options.size() >= 3);
        assertEquals("SCAN_APPS", generalPlan.options.get(0).actionType);

        SentinelDeviceGuardPlugin.AndroidTaskPlan boostPlan =
            SentinelDeviceGuardPlugin.planAndroidTaskOptions("My phone is slow, clean RAM and boost speed");
        assertTrue(boostPlan.options.size() >= 2);
        assertEquals("BOOST_RAM", boostPlan.options.get(0).actionType);
    }

    @Test
    public void testAndroidBackgroundBoostEligibility() {
        assertTrue(SentinelDeviceGuardPlugin.isEligibleBackgroundAppForBoost("com.instagram.android", "com.sentinelgrid.defense", false));
        assertFalse(SentinelDeviceGuardPlugin.isEligibleBackgroundAppForBoost("com.sentinelgrid.defense", "com.sentinelgrid.defense", false));
        assertFalse(SentinelDeviceGuardPlugin.isEligibleBackgroundAppForBoost("com.android.systemui", "com.sentinelgrid.defense", false));
        assertFalse(SentinelDeviceGuardPlugin.isEligibleBackgroundAppForBoost("com.android.phone", "com.sentinelgrid.defense", true));
    }

    @Test
    public void testNotificationUrlExtractionAndAppLockLogic() {
        List<String> urls = SentinelDeviceGuardPlugin.extractUrlsFromText(
            "Urgent KYC update at http://192.168.1.9/verify.apk now!"
        );
        assertEquals(1, urls.size());
        assertEquals("http://192.168.1.9/verify.apk", urls.get(0));

        Set<String> locked = new HashSet<>(Arrays.asList("com.whatsapp", "com.paypal.android.p2pmobile"));
        Map<String, Long> unlocked = new HashMap<>();
        long now = 10_000L;

        assertTrue(SentinelDeviceGuardPlugin.isAppLockTarget("com.whatsapp", locked, unlocked, now));
        assertFalse(SentinelDeviceGuardPlugin.isAppLockTarget("com.android.settings", locked, unlocked, now));

        unlocked.put("com.whatsapp", 25_000L);
        assertFalse(SentinelDeviceGuardPlugin.isAppLockTarget("com.whatsapp", locked, unlocked, now));
        assertTrue(SentinelDeviceGuardPlugin.isAppLockTarget("com.whatsapp", locked, unlocked, 30_000L));
    }
}
