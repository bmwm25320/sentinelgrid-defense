"""
Automated Verification Suite for SentinelGrid Windows Active Defense & FastAPI Endpoints
"""
import os
import sys
import shutil
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
import active_defense
import kaspersky_suite
import engine


class TestWindowsActiveDefense(unittest.TestCase):
    def test_01_vault_breach_audit_and_k_anonymity(self):
        # Verify weak + reused detection locally and HIBP check structure
        sample_entries = [
            {"id": "1", "service_name": "DemoWeak", "username": "u1", "password": "password"},
            {"id": "2", "service_name": "DemoReuse", "username": "u2", "password": "password"},
            {"id": "3", "service_name": "DemoStrong", "username": "u3", "password": "Sg!92#StrongUniquePass2026"},
        ]
        report = active_defense.audit_vault_breaches(sample_entries)
        self.assertEqual(report["total_entries"], 3)
        self.assertEqual(report["reused_count"], 2)
        self.assertGreaterEqual(report["weak_count"], 2)
        if report["hibp_reachable"]:
            self.assertGreaterEqual(report["breached_count"], 1)

    def test_02_firewall_ip_validation_and_block_unblock(self):
        with self.assertRaises(ValueError):
            active_defense.validate_blockable_ip("127.0.0.1")

        test_ip = "203.0.113.99"  # RFC 5737 TEST-NET-3 IP
        entry = active_defense.block_ip_firewall(test_ip, "Automated Unit Test Block")
        self.assertEqual(entry["ip"], test_ip)
        blocked = active_defense.load_blocked_ips()
        self.assertTrue(any(r["ip"] == test_ip for r in blocked))

        removed = active_defense.unblock_ip_firewall(test_ip)
        self.assertTrue(removed)
        blocked_after = active_defense.load_blocked_ips()
        self.assertFalse(any(r["ip"] == test_ip for r in blocked_after))

    def test_03_arp_mitm_and_hardware_privacy_guard(self):
        arp = active_defense.inspect_arp_mitm()
        self.assertIn(arp["status"], ("SAFE", "ALERT", "UNKNOWN"))

        hw = active_defense.inspect_hardware_privacy()
        self.assertEqual(hw["guard_status"], "ACTIVE")
        self.assertIsInstance(hw["webcam_in_use"], bool)
        self.assertIsInstance(hw["microphone_in_use"], bool)

    def test_04_usb_autorun_shield_detection(self):
        temp_usb = tempfile.mkdtemp(prefix="sg_usb_test_")
        try:
            autorun_path = os.path.join(temp_usb, "autorun.inf")
            with open(autorun_path, "w", encoding="utf-8") as f:
                f.write("[autorun]\nshellexecute=worm_payload.exe\n")

            res = active_defense.scan_usb_drive_path(temp_usb, engine.inspect_and_shield_file)
            self.assertEqual(res["threats_found"], 1)
            self.assertEqual(res["status"], "THREATS_NEUTRALIZED")
            # Cleanup generated test alert & quarantine item if created
            if res["threats"]:
                threat_sha = res["threats"][0].get("sha256")
                engine.alerts_store[:] = [a for a in engine.alerts_store if a.get("sha256") != threat_sha]
                q_list = engine.get_quarantine_metadata()
                for q in list(q_list):
                    if q.get("sha256") == threat_sha:
                        qp = q.get("quarantine_path")
                        if qp and os.path.exists(qp):
                            os.remove(qp)
                        q_list.remove(q)
                engine.save_quarantine_metadata(q_list)
        finally:
            shutil.rmtree(temp_usb, ignore_errors=True)

    def test_05_fastapi_endpoints_operational(self):
        client = TestClient(engine.app)
        self.assertEqual(client.get("/api/health").status_code, 200)
        self.assertEqual(client.get("/api/network/shield-status").status_code, 200)
        self.assertEqual(client.get("/api/privacy/hardware-guard").status_code, 200)
        self.assertEqual(client.get("/api/usb/status").status_code, 200)

    def test_06_gemini_background_copilot_plan_and_execute(self):
        client = TestClient(engine.app)
        # 1. Context & background toggle
        ctx = client.get("/api/gemini/context")
        self.assertEqual(ctx.status_code, 200)
        ctx_json = ctx.json()
        self.assertIn("hotkey", ctx_json)
        self.assertEqual(ctx_json["hotkey"], "Ctrl+Shift+G")

        summon = client.post("/api/gemini/summon")
        self.assertEqual(summon.status_code, 200)
        self.assertGreaterEqual(summon.json()["summon_counter"], 1)

        # 2. Plan Task -> get Options
        plan_resp = client.post("/api/gemini/plan", json={"task": "My laptop feels slow and check privacy"})
        self.assertEqual(plan_resp.status_code, 200)
        plan = plan_resp.json()
        self.assertTrue(len(plan["options"]) >= 2)

        # 3. Execute selected Option
        chosen = plan["options"][0]
        exec_resp = client.post(
            "/api/gemini/execute",
            json={
                "option_id": chosen["id"],
                "action_type": "hardware_privacy_audit",
                "params": {},
            },
        )
        self.assertEqual(exec_resp.status_code, 200)
        self.assertEqual(exec_resp.json()["status"], "executed")
        self.assertIn("Privacy Audit", exec_resp.json()["summary"])

    def test_07_useless_background_bloat_killer_and_ram_trim(self):
        # Verify bloat classifier protects OS/SentinelGrid/foreground while catching bloatware
        w_res = active_defense.classify_background_process("Widgets.exe", is_protected=False, is_foreground=False)
        self.assertTrue(w_res["can_safely_close"])
        self.assertTrue(w_res["is_useless_bloat"])

        fg_res = active_defense.classify_background_process("chrome.exe", is_protected=False, is_foreground=True)
        self.assertFalse(fg_res["can_safely_close"])

        wv_res = active_defense.classify_background_process("msedgewebview2.exe", is_protected=True, is_foreground=False)
        self.assertFalse(wv_res["can_safely_close"])

        client = TestClient(engine.app)
        diag = client.get("/api/ram/diagnostics")
        self.assertEqual(diag.status_code, 200)
        d_json = diag.json()
        self.assertIn("grouped_apps", d_json)
        self.assertIn("useless_bloat_count", d_json)

        trim = client.post("/api/ram/trim")
        self.assertEqual(trim.status_code, 200)
        self.assertEqual(trim.json()["status"], "success")
        self.assertGreaterEqual(trim.json()["trimmed_processes_count"], 1)

    def test_08_kaspersky_suite_endpoints_and_helpers(self):
        # 1. Disk junk scanner helper
        junk = kaspersky_suite.scan_disk_junk(max_files_per_dir=50)
        self.assertIn("total_files", junk)
        self.assertIn("total_mb", junk)
        self.assertIsInstance(junk["categories"], list)

        # 2. Winget parser unit check (deterministic tabular stdout)
        sample_winget = (
            "Name               Id                    Version   Available  Source\n"
            "--------------------------------------------------------------------\n"
            "Google Chrome      Google.Chrome         120.0.1   130.0.2    winget\n"
            "Notepad++          Notepad++.Notepad++   8.6.0     8.7.1      winget\n"
            "2 upgrades available.\n"
        )
        parsed = kaspersky_suite.parse_winget_upgrade_output(sample_winget)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["id"], "Google.Chrome")
        self.assertEqual(parsed[0]["severity"], "HIGH")
        self.assertEqual(parsed[1]["severity"], "MEDIUM")

        # 3. FastAPI Kaspersky Parity endpoints
        client = TestClient(engine.app)

        junk_res = client.get("/api/system/junk-scan")
        self.assertEqual(junk_res.status_code, 200)
        self.assertIn("categories", junk_res.json())

        startup_res = client.get("/api/startup/list")
        self.assertEqual(startup_res.status_code, 200)
        self.assertIn("entries", startup_res.json())

        protect_res = client.post("/api/startup/toggle", json={"name": "SentinelGridDefense", "enabled": False})
        self.assertEqual(protect_res.status_code, 403)

        sites_res = client.get("/api/safemoney/sites")
        self.assertEqual(sites_res.status_code, 200)
        self.assertGreaterEqual(len(sites_res.json()["sites"]), 4)

        phish_block = client.post("/api/safemoney/launch", json={"url": "http://paypal-login-security-alert.tk/verify"})
        self.assertEqual(phish_block.status_code, 403)

        zip_res = client.get("/api/download/browser-extension")
        self.assertEqual(zip_res.status_code, 200)
        self.assertIn("application/zip", zip_res.headers.get("content-type", ""))
        self.assertTrue(zip_res.content.startswith(b"PK"))

        plan_res = client.post("/api/gemini/plan", json={"task": "Open my bank portal in safe money"})
        self.assertEqual(plan_res.status_code, 200)
        self.assertTrue(any(opt["action_type"] == "open_safe_money" for opt in plan_res.json()["options"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
