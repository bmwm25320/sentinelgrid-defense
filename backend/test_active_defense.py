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


if __name__ == "__main__":
    unittest.main(verbosity=2)
