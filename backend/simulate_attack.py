"""
SentinelGrid Defense - Safe Stage Attack Simulator
Harmless educational proof-of-concept for demonstrating ransomware canary tripwire detection.
Attempts to rename/encrypt files in protected_zone, starting with the decoy canary file.
"""
import os
import sys
import time

def run_simulation():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    target_dir = os.path.join(current_dir, "protected_zone")
    
    print(f"[SIMULATOR] Starting simulated ransomware execution. PID: {os.getpid()}", flush=True)
    print(f"[SIMULATOR] Target directory: {target_dir}", flush=True)
    
    if not os.path.exists(target_dir):
        print(f"[SIMULATOR] Error: Target directory does not exist: {target_dir}", flush=True)
        return

    # Small pause to ensure process tree registration
    time.sleep(0.08)

    # Sort files: ransomware typically iterates alphabetically, hitting !000_System_Key.docx FIRST
    try:
        files = sorted(os.listdir(target_dir))
    except Exception as e:
        print(f"[SIMULATOR] Failed to list directory: {e}", flush=True)
        return

    print(f"[SIMULATOR] Discovered {len(files)} target files. Beginning encryption sequence...", flush=True)
    
    for filename in files:
        if filename.endswith(".locked"):
            continue
        filepath = os.path.join(target_dir, filename)
        if os.path.isfile(filepath):
            print(f"[SIMULATOR] Attempting to lock/encrypt: {filename} (PID: {os.getpid()})", flush=True)
            # Ransomware behavior: rename to .locked
            locked_path = filepath + ".locked"
            try:
                # Modify file first or rename
                with open(filepath, "a", encoding="utf-8", errors="ignore") as f:
                    f.write("\n[ENCRYPTED_BY_SIMULATOR_TEST]")
                os.rename(filepath, locked_path)
                print(f"[SIMULATOR] Locked {filename} -> {os.path.basename(locked_path)}", flush=True)
            except Exception as e:
                print(f"[SIMULATOR] File operation intercepted/failed: {e}", flush=True)
            
            # Simulated iteration delay
            time.sleep(0.2)

    print("[SIMULATOR] Simulation completed.", flush=True)

if __name__ == "__main__":
    run_simulation()
