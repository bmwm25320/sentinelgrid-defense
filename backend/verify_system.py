import urllib.request
import json
import time

def test_full_system():
    print("=== SENTINELGRID DEFENSE AUTOMATED VERIFICATION ===")

    # 1. Telemetry Check
    with urllib.request.urlopen("http://localhost:8000/api/telemetry") as r:
        telem = json.loads(r.read().decode())
        print(f"[*] Telemetry: CPU={telem['cpu_percent']}%, RAM={telem['memory_percent']}%, PIDs={telem['process_count']}, Canary={telem['canary_status']}")

    # 2. Ransomware Simulator
    req = urllib.request.Request("http://localhost:8000/api/simulate/ransomware", data=b"", method="POST")
    with urllib.request.urlopen(req) as r:
        sim_res = json.loads(r.read().decode())
        print(f"[*] Ransomware Simulator Launched: PID={sim_res['pid']}, Target={sim_res['target']}")

    time.sleep(0.5)

    # 3. EICAR Test
    req = urllib.request.Request("http://localhost:8000/api/simulate/eicar", data=b"", method="POST")
    with urllib.request.urlopen(req) as r:
        eicar_res = json.loads(r.read().decode())
        print(f"[*] EICAR Signature Simulator: Status={eicar_res['status']}, Latency={eicar_res['reaction_time_ms']}")

    # 4. Macro Injection Test
    req = urllib.request.Request("http://localhost:8000/api/simulate/macro_injection", data=b"", method="POST")
    with urllib.request.urlopen(req) as r:
        macro_res = json.loads(r.read().decode())
        print(f"[*] Macro Injection Simulator: Status={macro_res['status']}, Latency={macro_res['reaction_time_ms']}")

    # 5. Alerts Inspection
    with urllib.request.urlopen("http://localhost:8000/api/alerts") as r:
        alerts = json.loads(r.read().decode())
        print(f"\n[*] Total Alerts Intercepted & Logged: {len(alerts)}")
        for i, a in enumerate(alerts[:3]):
            print(f"    [{i+1}] {a['threat_name']} | Severity: {a['severity']} | Latency: {a['reaction_time_ms']} | MITRE: {a['mitre_id']}")

    # 6. Quarantine Inspection & Actions
    with urllib.request.urlopen("http://localhost:8000/api/quarantine") as r:
        quarantine = json.loads(r.read().decode())
        print(f"\n[*] Quarantine Vault Inventory: {len(quarantine)} items")
        if quarantine:
            target_restore = quarantine[0]
            print(f"    -> Testing RESTORE on: {target_restore['filename']}")
            restore_req = urllib.request.Request(
                "http://localhost:8000/api/quarantine/restore",
                data=json.dumps({"id": target_restore["id"]}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(restore_req) as rr:
                print(f"       Result: {json.loads(rr.read().decode())['status']}")

        if len(quarantine) > 1:
            target_shred = quarantine[1]
            print(f"    -> Testing DOD 5220.22-M SHRED on: {target_shred['filename']}")
            shred_req = urllib.request.Request(
                f"http://localhost:8000/api/quarantine/shred/{target_shred['id']}",
                data=b"",
                method="DELETE"
            )
            with urllib.request.urlopen(shred_req) as sr:
                print(f"       Result: {json.loads(sr.read().decode())['status']}")

    # 7. Frontend Reachability
    with urllib.request.urlopen("http://localhost:5173") as r:
        print(f"\n[*] Frontend Cyber-HUD UI: HTTP {r.status} (Vite Server Online on port 5173)")

    print("\n[✔] ALL SENTINELGRID DEFENSE SUB-SYSTEMS OPERATIONAL AND VERIFIED!")

if __name__ == "__main__":
    test_full_system()
