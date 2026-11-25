package com.sentinelgrid.defense;

import org.junit.Test;
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
}
