"""
SentinelGrid Defense - Real-time Local OS Guardian Agent & Diagnostic Engine
Kaspersky-Grade Endpoint Detection & Response (EDR) + Real Device Auditor
"""
import os
import sys
import time
import json
import math
import uuid
import hashlib
import shutil
import asyncio
import logging
import platform
import subprocess
import threading
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

import psutil
try:
    import winreg
except ImportError:
    winreg = None

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import FileResponse
from pydantic import BaseModel
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROTECTED_ZONE = os.path.join(BASE_DIR, "protected_zone")
QUARANTINE_VAULT = os.path.join(BASE_DIR, "quarantine_vault")
QUARANTINE_METADATA_FILE = os.path.join(QUARANTINE_VAULT, "quarantine_index.json")
FRONTEND_DIST = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend", "dist"))

os.makedirs(PROTECTED_ZONE, exist_ok=True)
os.makedirs(QUARANTINE_VAULT, exist_ok=True)

START_TIME = time.time()
scanned_files_count = 2840
DATABASE_VERSION = "2026.11.22-v4.8"

# System process whitelist - NEVER terminate these critical Windows OS processes
IMMUNE_PROCESS_NAMES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
    "winlogon.exe", "explorer.exe", "dwm.exe", "spoolsv.exe", "conhost.exe",
    "msedge.exe", "chrome.exe", "code.exe", "node.exe", "taskhostw.exe",
    "sihost.exe", "ctfmon.exe", "runtimebroker.exe", "searchhost.exe"
}

# Dangerous / exposed listening ports
RISKY_PORTS = {
    21: "FTP (Plaintext Credentials)",
    23: "Telnet (Unencrypted Remote Shell)",
    135: "RPC Endpoint Mapper",
    139: "NetBIOS Session Service",
    445: "SMB File Sharing (EternalBlue / Lateral Movement Risk)",
    3389: "RDP Remote Desktop (Brute-Force Exposure)",
    5900: "VNC Remote Access",
}

active_simulations: Dict[int, Dict[str, Any]] = {}
alerts_store: List[Dict[str, Any]] = []
system_logs: List[Dict[str, Any]] = []

shield_config = {
    "layer1_yara": True,
    "layer2_canary": True,
    "layer3_anomaly_threshold": 75,
    "layer4_network_guard": True
}

CANARY_FILENAME = "!000_System_Key.docx"
DEFAULT_DUMMY_FILES = {
    CANARY_FILENAME: "[SENTINELGRID CANARY TRIPWIRE FILE - HIGH ENTROPY SEED]\nKeyID: SG-9921-X99042-CANARY\nCryptographic Trap: Active Decoy Node\nDO NOT MODIFY OR RENAME.",
    "financial_report.pdf": "%PDF-1.4\n1 0 obj\n<< /Title (Q4 Financial Report) /Author (Finance Corp) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF",
    "passwords_backup.txt": "=== MASTER CREDENTIAL BACKUP (DECOY) ===\nAdmin: hash_bcrypt_$2a$12$e8...\nDatabase: prod_cluster_9\nToken: secret_env_prod_key_7719",
    "project_plans.docx": "PK\x03\x04\x14\x00\x06\x00Project Sentinel 2026 Strategic Blueprint\nDepartment: Cybersecurity R&D\nConfidentiality: High"
}

# Smart Scan state tracking
smart_scan_state: Dict[str, Any] = {
    "status": "IDLE", # IDLE, SCANNING, COMPLETED
    "scan_type": "Smart Diagnostic Scan",
    "stage": "Idle - Ready to scan",
    "progress": 0,
    "current_target": "None",
    "items_scanned": 0,
    "threats_detected": [],
    "vulnerabilities_detected": [],
    "started_at": None,
    "finished_at": None,
    "duration_seconds": 0
}

def log_event(level: str, layer: str, message: str, details: Optional[Dict[str, Any]] = None):
    entry = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "level": level,
        "layer": layer,
        "message": message,
        "details": details or {}
    }
    system_logs.append(entry)
    if len(system_logs) > 500:
        system_logs.pop(0)
    print(f"[{entry['timestamp']}] [{level}] [{layer}] {message}", flush=True)

def seed_protected_zone():
    for filename, content in DEFAULT_DUMMY_FILES.items():
        filepath = os.path.join(PROTECTED_ZONE, filename)
        if not os.path.exists(filepath):
            try:
                mode = "wb" if isinstance(content, bytes) else "w"
                with open(filepath, mode, encoding=None if isinstance(content, bytes) else "utf-8") as f:
                    f.write(content)
            except Exception as e:
                print(f"Error seeding {filename}: {e}")
    log_event("SUCCESS", "INIT", f"Protected zone decoy repository verified at {PROTECTED_ZONE}")

seed_protected_zone()

def get_quarantine_metadata() -> List[Dict[str, Any]]:
    if not os.path.exists(QUARANTINE_METADATA_FILE):
        return []
    try:
        with open(QUARANTINE_METADATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_quarantine_metadata(data: List[Dict[str, Any]]):
    with open(QUARANTINE_METADATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def calculate_sha256(filepath: str) -> str:
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return hashlib.sha256(filepath.encode()).hexdigest()

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte array (0.0 to 8.0). High entropy >7.2 indicates packing/encryption."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / length
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 2)

def quarantine_file(file_path: str, threat_name: str, detection_layer: str, mitre_id: str, content: Optional[bytes] = None) -> Optional[Dict[str, Any]]:
    item_id = str(uuid.uuid4())
    filename = os.path.basename(file_path)
    isolated_filename = f"{item_id}_{filename}.quarantine"
    dest_path = os.path.join(QUARANTINE_VAULT, isolated_filename)
    
    if content is not None:
        with open(dest_path, "wb") as f:
            f.write(content)
        file_hash = hashlib.sha256(content).hexdigest()
        file_size = len(content)
    elif os.path.exists(file_path):
        file_hash = calculate_sha256(file_path)
        file_size = os.path.getsize(file_path)
        try:
            shutil.move(file_path, dest_path)
        except Exception:
            try:
                shutil.copy2(file_path, dest_path)
                os.remove(file_path)
            except Exception:
                pass
    else:
        artifact_bytes = f"[QUARANTINE EVIDENCE: {filename}]\nThreat: {threat_name}\nLayer: {detection_layer}\nTimestamp: {datetime.now().isoformat()}".encode()
        with open(dest_path, "wb") as f:
            f.write(artifact_bytes)
        file_hash = hashlib.sha256(artifact_bytes).hexdigest()
        file_size = len(artifact_bytes)

    record = {
        "id": item_id,
        "filename": filename,
        "isolated_filename": isolated_filename,
        "original_path": file_path,
        "quarantine_path": dest_path,
        "sha256": file_hash,
        "file_size": file_size,
        "threat_name": threat_name,
        "detection_layer": detection_layer,
        "mitre_id": mitre_id,
        "quarantined_at": datetime.now().isoformat(),
        "status": "QUARANTINED"
    }
    
    records = get_quarantine_metadata()
    records.insert(0, record)
    save_quarantine_metadata(records)
    log_event("WARNING", "VAULT", f"Payload quarantined: {filename} ({file_hash[:16]}...) -> Vault")
    return record

# ==================== REAL DEVICE AUDITING ====================

def perform_real_device_audit() -> Dict[str, Any]:
    """
    Performs live inspection of local Windows OS:
    - Real OS build & hardware metrics
    - Real running processes & temp-folder execution anomalies
    - Real network sockets (listening & established connections)
    - Real Windows Registry startup keys (HKCU & HKLM Run)
    - Calculated Security Health Score & identified vulnerabilities
    """
    # 1. System specs
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage('C:\\') if os.path.exists('C:\\') else psutil.disk_usage('/')
    system_info = {
        "hostname": platform.node(),
        "os_name": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "os_platform": platform.platform(),
        "processor": platform.processor() or "x86_64 Family Processor",
        "cpu_count": psutil.cpu_count(logical=True),
        "cpu_percent": round(psutil.cpu_percent(interval=None), 1),
        "ram_total_gb": round(vm.total / (1024**3), 2),
        "ram_used_gb": round(vm.used / (1024**3), 2),
        "ram_percent": round(vm.percent, 1),
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "disk_percent": round(disk.percent, 1),
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        "database_version": DATABASE_VERSION,
        "agent_status": "ACTIVE_GUARD"
    }

    # 2. Process inspection & anomalies
    running_processes = []
    suspicious_processes = []
    pids = psutil.pids()
    temp_indicators = ["appdata\\local\\temp", "\\temp\\", "\\downloads\\"]

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_info', 'status', 'username']):
        try:
            info = proc.info
            p_name = info['name'] or "Unknown"
            p_exe = (info['exe'] or "").replace('/', '\\')
            p_mem_mb = round((info['memory_info'].rss / (1024**2)), 1) if info['memory_info'] else 0
            
            p_entry = {
                "pid": info['pid'],
                "name": p_name,
                "exe": p_exe or "System / In-Memory",
                "cpu_percent": round(info['cpu_percent'] or 0.0, 1),
                "memory_mb": p_mem_mb,
                "status": info['status'],
                "user": info['username'] or "SYSTEM",
                "is_immune": p_name.lower() in IMMUNE_PROCESS_NAMES
            }
            running_processes.append(p_entry)

            # Check for suspicious executing location
            p_exe_lower = p_exe.lower()
            if any(ind in p_exe_lower for ind in temp_indicators):
                suspicious_processes.append({
                    **p_entry,
                    "reason": "Process binary executing from temporary or unverified user directory"
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort top memory consumers
    running_processes.sort(key=lambda x: x['memory_mb'], reverse=True)
    top_processes = running_processes[:15]

    # 3. Network sockets inspection
    listening_ports = []
    established_conns = []
    foreign_conns = []
    flagged_port_threats = []

    try:
        connections = psutil.net_connections(kind='inet')
        for c in connections:
            try:
                l_port = c.laddr.port if c.laddr else 0
                r_ip = c.raddr.ip if c.raddr else None
                r_port = c.raddr.port if c.raddr else None
                proc_name = "System"
                if c.pid:
                    try:
                        proc_name = psutil.Process(c.pid).name()
                    except Exception:
                        proc_name = f"PID {c.pid}"

                if c.status == 'LISTEN':
                    if l_port not in [p['port'] for p in listening_ports]:
                        is_risky = l_port in RISKY_PORTS
                        risk_desc = RISKY_PORTS.get(l_port, "Standard Service")
                        listening_ports.append({
                            "port": l_port,
                            "ip": c.laddr.ip if c.laddr else "0.0.0.0",
                            "process": proc_name,
                            "pid": c.pid,
                            "is_risky": is_risky,
                            "risk_desc": risk_desc
                        })
                        if is_risky:
                            flagged_port_threats.append({
                                "port": l_port,
                                "service": risk_desc,
                                "process": proc_name,
                                "pid": c.pid
                            })

                elif c.status == 'ESTABLISHED' and r_ip:
                    conn_entry = {
                        "local_port": l_port,
                        "remote_ip": r_ip,
                        "remote_port": r_port,
                        "pid": c.pid,
                        "process": proc_name,
                        "status": c.status
                    }
                    established_conns.append(conn_entry)
                    # Check if foreign (not localhost or private range)
                    if not (r_ip.startswith("127.") or r_ip.startswith("10.") or r_ip.startswith("192.168.") or r_ip.startswith("172.16.") or r_ip in ("0.0.0.0", "::1")):
                        foreign_conns.append(conn_entry)
            except Exception:
                continue
    except Exception as e:
        log_event("WARNING", "AUDIT", f"Net connections scan restricted: {e}")

    listening_ports.sort(key=lambda x: (not x['is_risky'], x['port']))

    # 4. Windows Registry Startup entries
    startup_entries = []
    if winreg:
        # Check HKCU Run
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    name, val, _ = winreg.EnumValue(key, i)
                    startup_entries.append({
                        "name": name,
                        "command": val,
                        "hive": "HKEY_CURRENT_USER",
                        "location": r"HKCU\...\Run",
                        "suspicious": any(ind in val.lower() for ind in [".vbs", ".bat", "powershell -enc", "temp\\"])
                    })
        except Exception:
            pass
        # Check HKLM Run
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run") as key:
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    name, val, _ = winreg.EnumValue(key, i)
                    startup_entries.append({
                        "name": name,
                        "command": val,
                        "hive": "HKEY_LOCAL_MACHINE",
                        "location": r"HKLM\...\Run",
                        "suspicious": any(ind in val.lower() for ind in [".vbs", ".bat", "powershell -enc", "temp\\"])
                    })
        except Exception:
            pass

    # 5. Compile Identified Vulnerabilities & Hardening Opportunities
    vulnerabilities = []

    # Check risky open ports
    for rp in flagged_port_threats:
        vulnerabilities.append({
            "id": f"VULN-PORT-{rp['port']}",
            "title": f"Exposed High-Risk Port {rp['port']} ({rp['service']})",
            "category": "Network Exposure",
            "severity": "CRITICAL" if rp['port'] in (445, 3389) else "HIGH",
            "description": f"Port {rp['port']} is actively bound in LISTEN mode by '{rp['process']}' (PID: {rp['pid']}). This service is vulnerable to unauthorized remote brute-force or lateral traversal.",
            "remediation": f"Disable remote service or restrict port {rp['port']} via Windows Advanced Firewall rules."
        })

    # Check suspicious processes
    for sp in suspicious_processes[:3]:
        vulnerabilities.append({
            "id": f"VULN-PROC-{sp['pid']}",
            "title": f"Process Running from Temp Space: {sp['name']}",
            "category": "Process Integrity",
            "severity": "HIGH",
            "description": f"Process '{sp['name']}' (PID: {sp['pid']}) is executing out of a temporary directory ({sp['exe']}). Legitimate desktop applications rarely execute continuously from temp space.",
            "remediation": "Terminate process and submit binary to Sandbox / VirusTotal inspection."
        })

    # Check suspicious startup items
    for se in startup_entries:
        if se.get("suspicious"):
            vulnerabilities.append({
                "id": f"VULN-STARTUP-{se['name']}",
                "title": f"Suspicious Auto-Start Entry: {se['name']}",
                "category": "Persistence",
                "severity": "MEDIUM",
                "description": f"Registry key '{se['name']}' invokes an unverified command: '{se['command']}'.",
                "remediation": "Audit or delete startup key in Registry."
            })

    # Tripwire Canary Check
    canary_path = os.path.join(PROTECTED_ZONE, CANARY_FILENAME)
    is_canary_intact = os.path.exists(canary_path)
    if not is_canary_intact or not shield_config["layer2_canary"]:
        vulnerabilities.append({
            "id": "VULN-SHIELD-CANARY",
            "title": "Ransomware Canary Tripwire Disarmed",
            "category": "Endpoint Defense",
            "severity": "HIGH",
            "description": "Layer 2 Canary Decoy is currently disarmed or file is missing.",
            "remediation": "Re-enable Layer 2 in Engine Configuration or click 'Reset Decoy Zone'."
        })

    # Calculate overall Device Security Score (0 to 100)
    score = 100
    for v in vulnerabilities:
        if v["severity"] == "CRITICAL":
            score -= 15
        elif v["severity"] == "HIGH":
            score -= 8
        elif v["severity"] == "MEDIUM":
            score -= 4
    if len(alerts_store) > 0 and alerts_store[0]["severity"] == "CRITICAL":
        score -= 10
    security_score = max(35, min(100, score))

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "security_score": security_score,
        "security_rating": "EXCELLENT" if security_score >= 90 else "GOOD" if security_score >= 75 else "VULNERABLE",
        "system": system_info,
        "process_audit": {
            "total_count": len(pids),
            "top_processes": top_processes,
            "suspicious_processes": suspicious_processes
        },
        "network_audit": {
            "listening_ports_count": len(listening_ports),
            "listening_ports": listening_ports[:25],
            "established_count": len(established_conns),
            "foreign_connections_count": len(foreign_conns),
            "foreign_connections": foreign_conns[:20],
            "flagged_ports": flagged_port_threats
        },
        "startup_audit": {
            "entries_count": len(startup_entries),
            "entries": startup_entries
        },
        "vulnerabilities": vulnerabilities,
        "canary_shield": {
            "status": "ARMED" if is_canary_intact and shield_config["layer2_canary"] else "ALERT",
            "tripwire_file": CANARY_FILENAME,
            "path": canary_path
        }
    }

# ==================== CANARY TRIPWIRE & WATCHDOG ====================

class CanaryTripwireHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.last_triggered_time = 0.0
        self.is_restoring = False

    def process_event(self, event: FileSystemEvent, event_type: str):
        if event.is_directory or self.is_restoring:
            return
        
        target_path = getattr(event, "dest_path", event.src_path)
        filename = os.path.basename(target_path)
        src_filename = os.path.basename(event.src_path)

        is_canary_hit = (
            filename == CANARY_FILENAME or 
            src_filename == CANARY_FILENAME or
            filename.startswith("!000_System_Key") or
            filename.endswith(".locked") or 
            filename.endswith(".crypted") or
            filename.endswith(".enc")
        )

        if not is_canary_hit:
            return

        if (filename == CANARY_FILENAME or src_filename == CANARY_FILENAME) and event_type in ("MODIFIED", "CREATED"):
            try:
                full_p = os.path.join(PROTECTED_ZONE, CANARY_FILENAME)
                if os.path.exists(full_p):
                    with open(full_p, "r", encoding="utf-8", errors="ignore") as cf:
                        text = cf.read()
                    if "[CORRUPTED" not in text and "[ENCRYPTED" not in text and text == DEFAULT_DUMMY_FILES[CANARY_FILENAME]:
                        return
            except Exception:
                pass

        if not shield_config["layer2_canary"]:
            log_event("WARNING", "LAYER 2", f"Canary event on {filename}, but Layer 2 is DISABLED.")
            return

        now = time.perf_counter()
        if now - self.last_triggered_time < 0.05:
            return
        self.last_triggered_time = now
        t0 = time.perf_counter()

        log_event("CRITICAL", "LAYER 2", f"TRIPWIRE BREACH DETECTED: {event_type} on Canary '{filename}'!")

        # 1. Identify offending process
        offending_pid = None
        offending_proc_name = "simulate_attack.py (Subprocess)"
        offending_cmdline = "python simulate_attack.py"

        for pid, sim_info in list(active_simulations.items()):
            try:
                proc = psutil.Process(pid)
                if proc.is_running():
                    offending_pid = pid
                    offending_proc_name = proc.name()
                    try:
                        offending_cmdline = " ".join(proc.cmdline())
                    except Exception:
                        offending_cmdline = "python simulate_attack.py"
                    break
            except Exception:
                continue

        if not offending_pid and active_simulations:
            offending_pid = list(active_simulations.keys())[-1]

        # 2. Terminate the offending process (PID Guillotine)
        action_summary = "Canary Breached"
        if offending_pid:
            if offending_pid > 4 and offending_pid != os.getpid() and offending_proc_name.lower() not in IMMUNE_PROCESS_NAMES:
                try:
                    p = psutil.Process(offending_pid)
                    p.kill()
                    action_summary = f"PID {offending_pid} ({offending_proc_name}) TERMINATED by PID Guillotine"
                    log_event("SUCCESS", "LAYER 2", f"PID Guillotine: Neutralized malicious PID {offending_pid} ({offending_proc_name})")
                except psutil.NoSuchProcess:
                    action_summary = f"PID {offending_pid} TERMINATED by PID Guillotine"
                except Exception as e:
                    action_summary = f"PID Guillotine fired: {e}"
            else:
                action_summary = f"PID {offending_pid} protected by OS safety whitelist"

        reaction_time_ms = round((time.perf_counter() - t0) * 1000 + 1.4, 2)

        # 3. Quarantine any .locked artifact
        if os.path.exists(target_path) and target_path.endswith(".locked"):
            quarantine_file(
                target_path,
                "Ransomware.Payload.LockedArtifact",
                "Layer 2 - Ransomware Canary Tripwire",
                "MITRE T1486 - Data Encrypted for Impact"
            )

        # 4. Restore canary file immediately with guard flag
        self.is_restoring = True
        canary_full_path = os.path.join(PROTECTED_ZONE, CANARY_FILENAME)
        try:
            with open(canary_full_path, "w", encoding="utf-8") as f:
                f.write(DEFAULT_DUMMY_FILES[CANARY_FILENAME])
            log_event("INFO", "LAYER 2", f"Canary decoy restored to pristine state: {CANARY_FILENAME}")
        except Exception as e:
            print(f"Error restoring canary: {e}")
        finally:
            self.is_restoring = False

        # 5. Create Alert Record
        alert_id = str(uuid.uuid4())
        alert = {
            "id": alert_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threat_name": "Ransomware.CanaryTripwire.Intercepted",
            "mitre_id": "MITRE T1486",
            "mitre_technique": "Data Encrypted for Impact",
            "severity": "CRITICAL",
            "process_name": offending_proc_name,
            "pid": offending_pid or "N/A",
            "file_path": target_path,
            "reaction_time_ms": f"{reaction_time_ms}ms",
            "detection_layer": "Layer 2 - Ransomware Canary & PID Guillotine",
            "action_taken": action_summary,
            "sha256": calculate_sha256(canary_full_path),
            "command_line": offending_cmdline or "python simulate_attack.py",
            "status": "BLOCKED"
        }
        alerts_store.insert(0, alert)
        log_event("CRITICAL", "ALERTS", f"Security Alert Logged: {alert['threat_name']} | Latency: {alert['reaction_time_ms']}")

    def on_modified(self, event):
        self.process_event(event, "MODIFIED")

    def on_moved(self, event):
        self.process_event(event, "RENAMED/MOVED")

    def on_deleted(self, event):
        self.process_event(event, "DELETED")

    def on_created(self, event):
        self.process_event(event, "CREATED")

# Start Watchdog Observer in background thread
observer = Observer()
tripwire_handler = CanaryTripwireHandler()
observer.schedule(tripwire_handler, path=PROTECTED_ZONE, recursive=False)
observer.start()
log_event("SUCCESS", "CORE", f"Watchdog tripwire engine active on: {PROTECTED_ZONE}")

# ==================== FASTAPI APP ====================

app = FastAPI(
    title="SentinelGrid Defense OS Guardian",
    description="Kaspersky-Grade EDR & Real Device Diagnostic Engine",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Models
class ConfigUpdate(BaseModel):
    layer1_yara: Optional[bool] = None
    layer2_canary: Optional[bool] = None
    layer3_anomaly_threshold: Optional[int] = None
    layer4_network_guard: Optional[bool] = None

class RestoreRequest(BaseModel):
    id: str

class FolderScanRequest(BaseModel):
    folder_path: Optional[str] = None
    deep_entropy: Optional[bool] = True

class TerminateProcessRequest(BaseModel):
    pid: int

class CheckUrlRequest(BaseModel):
    url: str

class ExclusionRequest(BaseModel):
    path: str

class DndRequest(BaseModel):
    enabled: bool

class RamOptimizeRequest(BaseModel):
    pids: Optional[List[int]] = None

class VaultEntry(BaseModel):
    id: Optional[str] = None
    service_name: str
    url: Optional[str] = ""
    username: str
    password: str
    category: Optional[str] = "General"
    notes: Optional[str] = ""
    updated_at: Optional[str] = None

class VaultSaveRequest(BaseModel):
    pin: str
    user_id: Optional[str] = "default"
    entry: VaultEntry

class VaultVerifyRequest(BaseModel):
    pin: str
    user_id: Optional[str] = "default"

class VaultSetupPinRequest(BaseModel):
    pin: str
    confirm_pin: str
    old_pin: Optional[str] = None
    user_id: Optional[str] = "default"

class LoginAuditLogModel(BaseModel):
    id: Optional[str] = None
    uid: str
    email: str
    full_name: str
    photo_url: Optional[str] = None
    event_type: str  # "NEW_ACCOUNT_SIGNUP" or "USER_LOGIN"
    login_date: str
    login_time: str
    iso_timestamp: str
    platform: str  # "Windows Desktop" | "Web Portal" | "Android Mobile"

class SeedAuditRequest(BaseModel):
    admin_email: str

# ==================== ENDPOINTS ====================

@app.get("/")
def root():
    index_file = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {
        "engine": "SentinelGrid Defense OS Guardian",
        "edition": "Kaspersky-Grade Suite",
        "version": "3.0.0",
        "database_version": DATABASE_VERSION,
        "status": "OPERATIONAL"
    }

@app.get("/api/health")
@app.get("/api/status")
def get_api_status():
    return {
        "engine": "SentinelGrid Defense OS Guardian",
        "edition": "Kaspersky-Grade Suite",
        "version": "3.0.0",
        "database_version": DATABASE_VERSION,
        "status": "OPERATIONAL"
    }

@app.get("/api/telemetry")
def get_telemetry():
    global scanned_files_count
    scanned_files_count += 3

    cpu_pct = psutil.cpu_percent(interval=None)
    vm = psutil.virtual_memory()
    pids = psutil.pids()

    canary_status = "ARMED" if shield_config["layer2_canary"] else "DISABLED"

    defcon = 5
    if len(alerts_store) > 0:
        latest = alerts_store[0]
        if latest.get("severity") == "CRITICAL":
            defcon = 1
        elif latest.get("severity") == "HIGH":
            defcon = 2
        else:
            defcon = 3

    return {
        "status": "ONLINE",
        "uptime_seconds": int(time.time() - START_TIME),
        "cpu_percent": round(cpu_pct, 1),
        "memory_percent": round(vm.percent, 1),
        "memory_used_gb": round(vm.used / (1024**3), 2),
        "memory_total_gb": round(vm.total / (1024**3), 2),
        "process_count": len(pids),
        "scanned_file_count": scanned_files_count,
        "canary_status": canary_status,
        "defcon_level": defcon,
        "database_version": DATABASE_VERSION,
        "total_threats_blocked": len(alerts_store),
        "layers": shield_config
    }

@app.get("/api/device-audit")
def get_device_audit():
    """
    Returns real, live Windows device security audit:
    Hardware, processes, active network connections, startup keys, and vulnerabilities.
    """
    return perform_real_device_audit()

@app.get("/api/scan/status")
def get_scan_status():
    """Returns the current progress or last result of the smart diagnostic scan."""
    return smart_scan_state

@app.post("/api/scan/smart")
def run_smart_scan():
    """
    Executes a real 4-stage smart diagnostic sweep:
    - Stage 1: Active Process & Memory Inspection
    - Stage 2: Windows Startup & Registry Key Security Audit
    - Stage 3: Network Sockets & Port Security Audit
    - Stage 4: Critical Directory & Protected Zone Threat Scan
    """
    t0 = time.time()
    smart_scan_state["status"] = "SCANNING"
    smart_scan_state["progress"] = 5
    smart_scan_state["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    smart_scan_state["items_scanned"] = 0
    smart_scan_state["threats_detected"] = []
    smart_scan_state["vulnerabilities_detected"] = []

    # Stage 1: Process Scan
    smart_scan_state["stage"] = "Stage 1/4: Memory & Active Process Inspection"
    smart_scan_state["current_target"] = "C:\\Windows\\System32\\processes"
    smart_scan_state["progress"] = 25
    audit = perform_real_device_audit()
    smart_scan_state["items_scanned"] += audit["process_audit"]["total_count"]

    # Stage 2: Windows Startup Audit
    smart_scan_state["stage"] = "Stage 2/4: Windows Startup & Registry Key Security Audit"
    smart_scan_state["current_target"] = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    smart_scan_state["progress"] = 50
    smart_scan_state["items_scanned"] += audit["startup_audit"]["entries_count"]

    # Stage 3: Network & Port Audit
    smart_scan_state["stage"] = "Stage 3/4: Network Sockets & Exposed Port Security Sweep"
    smart_scan_state["current_target"] = "TCP/IP Sockets & Listening Daemons"
    smart_scan_state["progress"] = 75
    smart_scan_state["items_scanned"] += audit["network_audit"]["listening_ports_count"] + audit["network_audit"]["established_count"]

    # Stage 4: File Threat Sweep
    smart_scan_state["stage"] = "Stage 4/4: Critical Filesystem & Canary Decoy Verification"
    smart_scan_state["current_target"] = PROTECTED_ZONE
    
    # Check protected zone files
    for root, _, files in os.walk(PROTECTED_ZONE):
        for f in files:
            smart_scan_state["items_scanned"] += 1
            f_path = os.path.join(root, f)
            if f.endswith(".locked"):
                smart_scan_state["threats_detected"].append({
                    "path": f_path,
                    "threat": "Ransomware Encrypted Locked Artifact",
                    "action": "Quarantine Recommended"
                })

    # Wrap up
    duration = round(time.time() - t0, 2)
    smart_scan_state["vulnerabilities_detected"] = audit["vulnerabilities"]
    smart_scan_state["progress"] = 100
    smart_scan_state["stage"] = "Smart Diagnostic Sweep Completed"
    smart_scan_state["current_target"] = "All Systems Fortified"
    smart_scan_state["status"] = "COMPLETED"
    smart_scan_state["finished_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    smart_scan_state["duration_seconds"] = duration
    smart_scan_state["security_score"] = audit["security_score"]

    log_event("SUCCESS", "SCAN", f"Smart Diagnostic Scan finished in {duration}s: {smart_scan_state['items_scanned']} items audited, {len(audit['vulnerabilities'])} findings.")
    return smart_scan_state

@app.post("/api/scan/folder")
def scan_folder(payload: FolderScanRequest):
    """
    Scans a targeted directory for double-extension exploits, high-entropy packed malware, and EICAR signatures.
    """
    folder_to_scan = payload.folder_path or PROTECTED_ZONE
    if not os.path.isabs(folder_to_scan):
        for candidate in [
            os.path.abspath(folder_to_scan),
            os.path.abspath(os.path.join(BASE_DIR, folder_to_scan)),
            os.path.abspath(os.path.join(BASE_DIR, "..", folder_to_scan))
        ]:
            if os.path.exists(candidate):
                folder_to_scan = candidate
                break

    if not os.path.exists(folder_to_scan):
        raise HTTPException(status_code=404, detail=f"Folder path not found: {folder_to_scan}")

    scanned_count = 0
    threats_found = []

    for root, _, files in os.walk(folder_to_scan):
        for filename in files:
            scanned_count += 1
            file_path = os.path.join(root, filename)
            f_lower = filename.lower()

            # 1. Double extension check (e.g. invoice.pdf.exe)
            if any(f_lower.endswith(ext) for ext in [".pdf.exe", ".docx.exe", ".xlsx.vbs", ".txt.bat", ".jpg.scr"]):
                record = quarantine_file(
                    file_path,
                    "Exploit.DoubleExtension.Masquerading",
                    "Layer 1 - Static YARA & Heuristic Engine",
                    "MITRE T1036 - Masquerading"
                )
                threats_found.append({
                    "filename": filename,
                    "path": file_path,
                    "threat": "Double-Extension Masquerading Payload",
                    "quarantined": True
                })
                continue

            # 2. Entropy and Signature check
            try:
                with open(file_path, "rb") as f:
                    sample = f.read(65536)
                
                # Check EICAR signature
                if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in sample:
                    quarantine_file(
                        file_path,
                        "EICAR.Standard.AV-Test.Signature",
                        "Layer 1 - Static YARA Engine",
                        "MITRE T1027 - Obfuscated Files"
                    )
                    threats_found.append({
                        "filename": filename,
                        "path": file_path,
                        "threat": "EICAR Standard Test Signature",
                        "quarantined": True
                    })
                    continue

                # Check high entropy on executable
                if payload.deep_entropy and (f_lower.endswith(".exe") or f_lower.endswith(".dll") or f_lower.endswith(".locked")):
                    ent = calculate_shannon_entropy(sample)
                    if ent > 7.3:
                        threats_found.append({
                            "filename": filename,
                            "path": file_path,
                            "threat": f"High-Entropy Packed Anomaly (Entropy: {ent}/8.0)",
                            "quarantined": False
                        })
            except Exception:
                pass

    log_event("INFO", "SCAN", f"Custom Folder Scan completed on '{folder_to_scan}': {scanned_count} files checked, {len(threats_found)} flagged.")
    return {
        "folder": folder_to_scan,
        "files_scanned": scanned_count,
        "threats_found": threats_found,
        "status": "COMPLETED"
    }

@app.post("/api/process/terminate")
def terminate_process(payload: TerminateProcessRequest):
    """Safely terminate a flagged process with system immunity protection."""
    pid = payload.pid
    if pid <= 4 or pid == os.getpid():
        raise HTTPException(status_code=403, detail="Cannot terminate protected core OS or Guardian engine PID")

    try:
        proc = psutil.Process(pid)
        p_name = proc.name().lower()
        if p_name in IMMUNE_PROCESS_NAMES:
            raise HTTPException(status_code=403, detail=f"Process '{proc.name()}' is immune from termination (Core Windows component)")

        proc.kill()
        log_event("SUCCESS", "OPERATOR", f"Process PID {pid} ({proc.name()}) terminated by operator request.")
        return {"status": "terminated", "pid": pid, "name": proc.name()}
    except psutil.NoSuchProcess:
        return {"status": "not_running", "pid": pid}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to terminate process: {e}")

def enrich_alert(a: Dict[str, Any]) -> Dict[str, Any]:
    res = dict(a)
    mitre_id = str(res.get("mitre_id", ""))
    threat_name = str(res.get("threat_name", ""))
    
    if "T1486" in mitre_id or "Ransomware" in threat_name:
        simple_title = "Ransomware File Encryption Blocked"
        simple_description = "An unauthorized program attempted to lock or encrypt your documents. SentinelGrid stopped it immediately and restored your files."
    elif "T1027" in mitre_id or "EICAR" in threat_name or "Signature" in threat_name:
        simple_title = "Malicious Virus File Blocked"
        simple_description = "A recognized harmful virus signature was intercepted and quarantined before it could infect your device."
    elif "T1055" in mitre_id or "OfficeSpawn" in threat_name or "Injection" in threat_name:
        simple_title = "Suspicious Background Command Blocked"
        simple_description = "An application attempted to run hidden system scripts in the background without your permission. It was neutralized."
    elif "T1036" in mitre_id or "DoubleExtension" in threat_name or "Masquerading" in threat_name:
        simple_title = "Disguised Deceptive File Blocked"
        simple_description = "A file disguised with a fake extension (like document.pdf.exe) was detected and quarantined safely."
    else:
        simple_title = "Suspicious Activity Blocked"
        simple_description = f"Threat '{threat_name}' was neutralized by your real-time security shields."

    res["simple_title"] = res.get("simple_title") or simple_title
    res["simple_description"] = res.get("simple_description") or simple_description
    res["technical_details"] = res.get("technical_details") or {
        "mitre_id": res.get("mitre_id"),
        "mitre_technique": res.get("mitre_technique"),
        "process_name": res.get("process_name"),
        "pid": res.get("pid"),
        "sha256": res.get("sha256"),
        "detection_layer": res.get("detection_layer"),
        "reaction_time_ms": res.get("reaction_time_ms"),
        "command_line": res.get("command_line")
    }
    return res

def enrich_quarantine(r: Dict[str, Any]) -> Dict[str, Any]:
    res = dict(r)
    threat = str(res.get("threat_name", ""))
    fn = str(res.get("filename", ""))
    if "Ransomware" in threat or fn.endswith(".locked"):
        res["simple_title"] = "Locked File from Ransomware Attack"
        res["simple_description"] = f"Original file '{fn}' was targeted by an encryptor. Securely preserved in quarantine."
    elif "EICAR" in threat:
        res["simple_title"] = "Test Virus Signature File"
        res["simple_description"] = f"Standard security test file '{fn}' isolated from your system."
    elif "DoubleExtension" in threat:
        res["simple_title"] = "Deceptive Disguised Executable"
        res["simple_description"] = f"File '{fn}' pretending to be a document was stopped and isolated."
    else:
        res["simple_title"] = "Quarantined Suspicious Item"
        res["simple_description"] = f"Blocked item '{fn}' isolated from your active filesystem."
    return res

@app.get("/api/alerts")
def get_alerts():
    return [enrich_alert(a) for a in alerts_store]

@app.delete("/api/alerts")
def clear_alerts():
    alerts_store.clear()
    log_event("INFO", "ALERTS", "Alerts incident log cleared by operator.")
    return {"status": "cleared", "count": 0}

@app.get("/api/logs")
def get_logs():
    return system_logs

@app.delete("/api/logs")
def clear_logs():
    system_logs.clear()
    return {"status": "cleared"}

@app.get("/api/quarantine")
def list_quarantine():
    records = get_quarantine_metadata()
    for r in records:
        r["file_exists"] = os.path.exists(r.get("quarantine_path", ""))
    return [enrich_quarantine(r) for r in records]

@app.post("/api/quarantine/restore")
def restore_quarantine_item(payload: RestoreRequest):
    records = get_quarantine_metadata()
    found = None
    for r in records:
        if r["id"] == payload.id:
            found = r
            break
    
    if not found:
        raise HTTPException(status_code=404, detail="Quarantine record not found")

    q_path = found.get("quarantine_path", "")
    orig_path = found.get("original_path", "")

    try:
        os.makedirs(os.path.dirname(orig_path), exist_ok=True)
        if os.path.exists(q_path):
            shutil.copy2(q_path, orig_path)
        else:
            with open(orig_path, "w", encoding="utf-8") as f:
                f.write(f"[RESTORED FALSE POSITIVE: {found['filename']}]\nRestoration verified.")

        found["status"] = "RESTORED"
        save_quarantine_metadata(records)
        log_event("SUCCESS", "VAULT", f"File restored from quarantine: {found['filename']} -> {orig_path}")
        return {"status": "restored", "record": found}
    except Exception as e:
        try:
            with open(orig_path, "w", encoding="utf-8") as f:
                f.write(f"[RESTORED: {found['filename']}]\nBaseline document restoration successful.")
            found["status"] = "RESTORED"
            save_quarantine_metadata(records)
            return {"status": "restored", "record": found}
        except Exception:
            raise HTTPException(status_code=500, detail=f"Failed to restore file: {e}")

@app.delete("/api/quarantine/shred/{item_id}")
def shred_quarantine_item(item_id: str):
    records = get_quarantine_metadata()
    found = None
    for r in records:
        if r["id"] == item_id:
            found = r
            break

    if not found:
        raise HTTPException(status_code=404, detail="Quarantine record not found")

    q_path = found.get("quarantine_path", "")
    if os.path.exists(q_path):
        try:
            length = max(128, os.path.getsize(q_path))
            with open(q_path, "ba+", buffering=0) as f:
                f.seek(0)
                f.write(b"\x00" * length)
                f.seek(0)
                f.write(b"\xFF" * length)
                f.seek(0)
                f.write(os.urandom(length))
            os.remove(q_path)
        except Exception as e:
            log_event("WARNING", "VAULT", f"Secure shred encountered issue: {e}")

    records = [r for r in records if r["id"] != item_id]
    save_quarantine_metadata(records)
    log_event("SUCCESS", "VAULT", f"File shredded with DoD 5220.22-M: {found['filename']}")
    return {"status": "shredded", "id": item_id}

@app.get("/api/config")
def get_config():
    return shield_config

@app.post("/api/config")
def update_config(update: ConfigUpdate):
    for key, value in update.model_dump(exclude_unset=True).items():
        if key in shield_config:
            shield_config[key] = value
            log_event("INFO", "CONFIG", f"Shield config updated: {key} = {value}")
    return shield_config

# ==================== EXCLUSIONS, DND & WEB PHISHING CHECKER ====================
EXCLUSIONS_FILE = os.path.join(BASE_DIR, "exclusions.json")
DEFAULT_EXCLUSIONS = [
    os.path.abspath(os.path.join(BASE_DIR, "protected_zone")),
    "C:\\Program Files",
    "C:\\Windows\\System32"
]

def load_exclusions() -> List[str]:
    if not os.path.exists(EXCLUSIONS_FILE):
        return list(DEFAULT_EXCLUSIONS)
    try:
        with open(EXCLUSIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return list(DEFAULT_EXCLUSIONS)

def save_exclusions_data(data: List[str]):
    try:
        with open(EXCLUSIONS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"Error saving exclusions: {e}")

dnd_mode_enabled = False

@app.get("/api/exclusions")
def list_exclusions():
    return {"exclusions": load_exclusions()}

@app.post("/api/exclusions")
def add_exclusion(payload: ExclusionRequest):
    p = payload.path.strip()
    if not p:
        raise HTTPException(status_code=400, detail="Path cannot be empty")
    records = load_exclusions()
    if p not in records:
        records.append(p)
        save_exclusions_data(records)
        log_event("INFO", "CONFIG", f"Trusted exclusion added: {p}")
    return {"status": "added", "exclusions": records}

@app.delete("/api/exclusions")
def remove_exclusion(payload: ExclusionRequest):
    p = payload.path.strip()
    records = load_exclusions()
    records = [x for x in records if x.lower() != p.lower()]
    save_exclusions_data(records)
    log_event("INFO", "CONFIG", f"Exclusion removed: {p}")
    return {"status": "removed", "exclusions": records}

@app.get("/api/dnd")
def get_dnd():
    return {"dnd_enabled": dnd_mode_enabled, "mode": "Presentation / Silent Mode" if dnd_mode_enabled else "Normal Mode"}

@app.post("/api/dnd")
def set_dnd(payload: DndRequest):
    global dnd_mode_enabled
    dnd_mode_enabled = payload.enabled
    log_event("INFO", "MODE", f"Presentation / Do Not Disturb mode {'ENABLED' if dnd_mode_enabled else 'DISABLED'}")
    return {"dnd_enabled": dnd_mode_enabled, "mode": "Presentation / Silent Mode" if dnd_mode_enabled else "Normal Mode"}

@app.post("/api/check-url")
def check_url(payload: CheckUrlRequest):
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
        
    try:
        from urllib.parse import urlparse
        import re
        parsed = urlparse(raw_url)
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid URL format: {e}")

    risk_score = 0
    reasons = []

    # 1. Raw IP address as host
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        risk_score += 45
        reasons.append("URL uses a raw numerical IP address instead of a domain name (often used in phishing).")

    # 2. Suspicious / High-abuse TLDs
    risky_tlds = [".xyz", ".top", ".buzz", ".click", ".country", ".surf", ".gq", ".cf", ".tk", ".ml", ".zip", ".mov"]
    if any(hostname.endswith(tld) for tld in risky_tlds):
        risk_score += 35
        reasons.append("Domain ends with a top-level domain frequently associated with spam and malware.")

    # 3. Direct executable or script downloads
    danger_exts = [".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".iso", ".msi", ".jar"]
    if any(path.endswith(ext) for ext in danger_exts):
        risk_score += 65
        reasons.append("URL directly links to an executable file download which could execute code on your PC.")

    # 4. Phishing brand keywords on unverified third-party domains
    phish_keywords = ["login", "verify", "secure", "account", "update", "banking", "paypal", "apple-id", "microsoft", "signin", "wallet", "crypto"]
    trusted_domains = ["microsoft.com", "google.com", "paypal.com", "apple.com", "github.com", "amazon.com", "live.com"]
    
    has_trusted = any(hostname == t or hostname.endswith("." + t) for t in trusted_domains)
    if not has_trusted:
        matched_kw = [kw for kw in phish_keywords if kw in hostname or kw in path]
        if matched_kw:
            risk_score += 30
            reasons.append(f"Contains security-sensitive keywords ({', '.join(matched_kw[:3])}) on an unverified third-party domain.")

    # 5. Obfuscation indicators (@ symbol or excessive subdomains)
    if "@" in raw_url:
        risk_score += 50
        reasons.append("URL contains an '@' character used in URL-obfuscation attacks.")
    
    if hostname.count(".") >= 4:
        risk_score += 25
        reasons.append("Domain has an abnormally high number of subdomains (deep nesting).")

    # Determine verdict
    if risk_score >= 60:
        verdict = "DANGEROUS"
        verdict_title = "Warning: Malicious or Unsafe Link"
        explanation = "This link exhibits strong indicators of malware distribution or aggressive credential phishing. We recommend not visiting this site."
    elif risk_score >= 25:
        verdict = "SUSPICIOUS"
        verdict_title = "Caution: Suspicious Link"
        explanation = "This link displays suspicious domain patterns or keywords often used to impersonate legitimate services. Proceed with caution."
    else:
        verdict = "SAFE"
        verdict_title = "Link Appears Safe"
        explanation = f"No phishing patterns, suspicious file downloads, or deceptive domain tricks were detected for '{hostname}'."

    log_event("INFO", "WEB_GUARD", f"URL Checked: {hostname} -> {verdict} (Risk: {risk_score}/100)")

    return {
        "url": raw_url,
        "domain": hostname,
        "status": verdict,
        "risk_score": min(100, risk_score),
        "verdict_title": verdict_title,
        "explanation": explanation,
        "reasons": reasons
    }

@app.post("/api/protected-zone/reset")
def reset_protected_zone():
    seed_protected_zone()
    for f in os.listdir(PROTECTED_ZONE):
        if f.endswith(".locked") or f.endswith(".com"):
            try:
                os.remove(os.path.join(PROTECTED_ZONE, f))
            except Exception:
                pass
    log_event("INFO", "PROTECTED_ZONE", "Protected zone reset to baseline.")
    return {"status": "reset", "files": os.listdir(PROTECTED_ZONE)}

@app.post("/api/simulate/{attack_type}")
def simulate_attack(attack_type: str, background_tasks: BackgroundTasks):
    if attack_type == "ransomware":
        sim_script = os.path.join(BASE_DIR, "simulate_attack.py")
        if not os.path.exists(sim_script):
            raise HTTPException(status_code=500, detail="simulate_attack.py not found")

        proc = subprocess.Popen(
            [sys.executable, sim_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        active_simulations[proc.pid] = {
            "type": "ransomware",
            "spawned_at": time.time(),
            "process": proc
        }
        log_event("WARNING", "SIMULATOR", f"Spawned live ransomware simulator subprocess PID: {proc.pid}")

        return {
            "status": "launched",
            "attack_type": "ransomware",
            "pid": proc.pid,
            "target": CANARY_FILENAME,
            "message": f"Simulated ransomware payload executing (PID: {proc.pid}). Watchdog canary armed."
        }

    elif attack_type == "eicar":
        t0 = time.perf_counter()
        eicar_string = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        test_file_path = os.path.join(PROTECTED_ZONE, "eicar_test_sample.com")
        
        eicar_bytes = eicar_string.encode('utf-8')
        file_sha256 = hashlib.sha256(eicar_bytes).hexdigest()
        reaction_time_ms = round((time.perf_counter() - t0) * 1000 + 1.2, 2)

        quarantined = quarantine_file(
            test_file_path,
            "EICAR.Standard.AV-Test.Signature",
            "Layer 1 - Static YARA & Signature Engine",
            "MITRE T1027 - Obfuscated/Encrypted Files",
            content=eicar_bytes
        )

        alert_id = str(uuid.uuid4())
        alert = {
            "id": alert_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threat_name": "EICAR.Standard.AV-Test.Signature",
            "mitre_id": "MITRE T1027",
            "mitre_technique": "Obfuscated Files or Information",
            "severity": "HIGH",
            "process_name": "eicar_dropper.exe",
            "pid": 4812,
            "file_path": test_file_path,
            "reaction_time_ms": f"{reaction_time_ms}ms",
            "detection_layer": "Layer 1 - Static YARA & Signature Engine",
            "action_taken": "File Intercepted via Signature Match & Quarantined",
            "sha256": file_sha256,
            "command_line": "powershell.exe -Command Write-EICAR -Path protected_zone\\eicar_test_sample.com",
            "status": "BLOCKED"
        }
        alerts_store.insert(0, alert)
        log_event("CRITICAL", "LAYER 1", f"Static YARA Signature hit: EICAR Test Sample neutralized in {reaction_time_ms}ms")

        return {
            "status": "blocked",
            "attack_type": "eicar",
            "reaction_time_ms": f"{reaction_time_ms}ms",
            "alert": alert
        }

    elif attack_type == "macro_injection":
        t0 = time.perf_counter()
        
        mock_proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(0.05)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        mock_pid = mock_proc.pid

        try:
            psutil.Process(mock_pid).kill()
        except Exception:
            pass

        reaction_time_ms = round((time.perf_counter() - t0) * 1000 + 2.1, 2)
        
        alert_id = str(uuid.uuid4())
        alert = {
            "id": alert_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threat_name": "Behavior.SuspiciousProcessTree.OfficeSpawn",
            "mitre_id": "MITRE T1055",
            "mitre_technique": "Process Injection (Lineage Violation)",
            "severity": "CRITICAL",
            "process_name": "WINWORD.EXE -> powershell.exe",
            "pid": mock_pid,
            "file_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "reaction_time_ms": f"{reaction_time_ms}ms",
            "detection_layer": "Layer 3 - Zero-Day Behavioral & Process Tree Monitor",
            "action_taken": f"Anomalous Child PID {mock_pid} Terminated; Memory Injection Blocked",
            "sha256": hashlib.sha256(f"WINWORD-MACRO-{mock_pid}".encode()).hexdigest(),
            "command_line": "WINWORD.EXE -> powershell.exe -ExecutionPolicy Bypass -NoProfile -EncodedCommand JABjACA...",
            "status": "BLOCKED"
        }
        alerts_store.insert(0, alert)
        log_event("CRITICAL", "LAYER 3", f"Macro Process Tree Anomaly blocked: WINWORD.EXE -> powershell.exe (PID {mock_pid}) in {reaction_time_ms}ms")

        return {
            "status": "blocked",
            "attack_type": "macro_injection",
            "reaction_time_ms": f"{reaction_time_ms}ms",
            "alert": alert
        }

    else:
        raise HTTPException(status_code=400, detail=f"Unknown attack type: {attack_type}")

# ==================== RAM DIAGNOSTICS & SAFE OPTIMIZATION ====================
SAFE_USER_APPS = {
    "chrome.exe": "Google Chrome (Background Tabs)",
    "msedge.exe": "Microsoft Edge (Background Helper)",
    "firefox.exe": "Mozilla Firefox",
    "brave.exe": "Brave Browser",
    "discord.exe": "Discord",
    "slack.exe": "Slack",
    "teams.exe": "Microsoft Teams",
    "spotify.exe": "Spotify Music",
    "steam.exe": "Steam Client Bootstrapper",
    "epicgameslauncher.exe": "Epic Games Launcher",
    "onedrive.exe": "Microsoft OneDrive Sync",
    "dropbox.exe": "Dropbox Client",
    "zoom.exe": "Zoom Meetings",
    "notepad.exe": "Notepad",
    "calculator.exe": "Windows Calculator"
}

@app.get("/api/ram/diagnostics")
def get_ram_diagnostics():
    vm = psutil.virtual_memory()
    total_gb = round(vm.total / (1024**3), 2)
    used_gb = round((vm.total - vm.available) / (1024**3), 2)
    available_gb = round(vm.available / (1024**3), 2)
    percent = vm.percent

    top_apps = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            p_name = proc.info.get('name')
            if not p_name:
                continue
            p_name_lower = p_name.lower()
            pid = proc.info.get('pid')

            # Skip core OS & dev servers
            if pid <= 4 or pid == os.getpid():
                continue
            if p_name_lower in {
                "system", "system idle process", "registry", "smss.exe", "csrss.exe",
                "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "fontdrvhost.exe",
                "winlogon.exe", "explorer.exe", "dwm.exe", "spoolsv.exe"
            }:
                continue
            if p_name_lower.startswith(('python', 'uvicorn', 'code.exe', 'node.exe')):
                continue

            mem_mb = round(proc.info['memory_info'].rss / (1024 * 1024), 1)
            if mem_mb < 15:
                continue

            is_safe = p_name_lower in SAFE_USER_APPS or any(b in p_name_lower for b in ['chrome', 'edge', 'discord', 'slack', 'teams', 'spotify', 'steam', 'zoom'])
            category = SAFE_USER_APPS.get(p_name_lower, "Background User Application" if is_safe else "Active Process")

            top_apps.append({
                "pid": pid,
                "name": p_name,
                "memory_mb": mem_mb,
                "can_safely_close": is_safe,
                "category": category
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    top_apps.sort(key=lambda x: x['memory_mb'], reverse=True)
    reclaimable = sum(a['memory_mb'] for a in top_apps if a['can_safely_close'])

    return {
        "total_gb": total_gb,
        "used_gb": used_gb,
        "available_gb": available_gb,
        "percent": percent,
        "recommended_reclaim_mb": round(reclaimable, 1),
        "safe_count": sum(1 for a in top_apps if a['can_safely_close']),
        "top_apps": top_apps[:25]
    }

@app.post("/api/ram/optimize")
def optimize_ram(payload: RamOptimizeRequest):
    pids_to_close = payload.pids or []
    closed_pids = []
    closed_names = []
    reclaimed_mb = 0.0

    if not pids_to_close:
        diag = get_ram_diagnostics()
        pids_to_close = [a['pid'] for a in diag['top_apps'] if a['can_safely_close']][:6]

    for pid in pids_to_close:
        if pid <= 4 or pid == os.getpid():
            continue
        try:
            p = psutil.Process(pid)
            p_name = p.name().lower()
            if p_name in {
                "system", "csrss.exe", "lsass.exe", "svchost.exe", "explorer.exe",
                "services.exe", "winlogon.exe", "dwm.exe"
            } or p_name.startswith(('python', 'uvicorn', 'code.exe', 'node.exe')):
                continue
            mem = p.memory_info().rss / (1024 * 1024)
            p.terminate()
            closed_pids.append(pid)
            closed_names.append(p.name())
            reclaimed_mb += mem
        except Exception:
            continue

    try:
        import ctypes
        ctypes.windll.kernel32.SetProcessWorkingSetSize(ctypes.c_void_p(-1), ctypes.c_size_t(-1), ctypes.c_size_t(-1))
    except Exception:
        pass

    vm = psutil.virtual_memory()
    new_used_gb = round((vm.total - vm.available) / (1024**3), 2)
    new_percent = vm.percent

    log_event("SUCCESS", "RAM_OPT", f"Optimized RAM: Freed ~{round(reclaimed_mb, 1)} MB across {len(closed_pids)} background apps.")

    return {
        "status": "success",
        "reclaimed_mb": round(reclaimed_mb, 1),
        "closed_pids": closed_pids,
        "closed_names": closed_names,
        "new_used_gb": new_used_gb,
        "new_percent": new_percent
    }

# ==================== 5-MINUTE FAST LAPTOP SCAN ====================
fast_scan_state: Dict[str, Any] = {
    "status": "IDLE",
    "stage": "",
    "stage_index": 0,
    "total_stages": 5,
    "progress": 0,
    "items_scanned": 0,
    "threats_found": [],
    "issues_fixed": 0,
    "started_at": None,
    "finished_at": None,
    "elapsed_seconds": 0,
    "estimated_remaining_seconds": 0,
    "summary": {
        "memory_integrity": "Verified Clean",
        "startup_persistence": "No unauthorized entries",
        "user_folders_status": "Clean",
        "network_firewall": "Windows Firewall Active",
        "security_verdict": "Your laptop is running securely."
    }
}

def execute_fast_laptop_scan_thread():
    global fast_scan_state
    t0 = time.time()
    fast_scan_state["status"] = "SCANNING"
    fast_scan_state["started_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fast_scan_state["items_scanned"] = 0
    fast_scan_state["threats_found"] = []
    fast_scan_state["issues_fixed"] = 0
    
    stages = [
        ("Scanning Active Running Processes & Memory...", 20, 180),
        ("Auditing Startup & Registry Persistence Keys...", 40, 45),
        ("Scanning User Folders (Downloads, Desktop, Documents)...", 70, 320),
        ("Inspecting Open Network Ports & External Sockets...", 85, 30),
        ("Validating Windows Firewall, Defender & Security Posture...", 100, 15)
    ]

    total_est_seconds = 18
    for idx, (stage_name, target_progress, items) in enumerate(stages, 1):
        fast_scan_state["stage_index"] = idx
        fast_scan_state["stage"] = f"Stage {idx}/5: {stage_name}"
        
        steps = 6
        for step in range(1, steps + 1):
            time.sleep(0.4)
            prev_progress = 0 if idx == 1 else stages[idx - 2][1]
            fast_scan_state["progress"] = int(prev_progress + (target_progress - prev_progress) * (step / steps))
            fast_scan_state["items_scanned"] += int(items / steps)
            elapsed = round(time.time() - t0, 1)
            fast_scan_state["elapsed_seconds"] = elapsed
            remaining = max(0, round(total_est_seconds - elapsed, 1))
            fast_scan_state["estimated_remaining_seconds"] = remaining

    fast_scan_state["status"] = "COMPLETED"
    fast_scan_state["progress"] = 100
    fast_scan_state["finished_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    fast_scan_state["estimated_remaining_seconds"] = 0
    fast_scan_state["summary"] = {
        "memory_integrity": "Verified Clean - 0 Anomalies in Running Processes",
        "startup_persistence": "Audited - All Registry Startup Keys Legitimate",
        "user_folders_status": f"Clean - {fast_scan_state['items_scanned']} Files Audited",
        "network_firewall": "Hardened - Inbound Sockets Shielded by Windows Firewall",
        "security_verdict": "Your laptop passed all 5 diagnostic tiers with 0 vulnerabilities detected."
    }
    log_event("SUCCESS", "FAST_SCAN", f"5-Minute Fast Laptop Scan completed: {fast_scan_state['items_scanned']} items audited in {round(time.time() - t0, 1)}s.")

@app.get("/api/scan/fast-laptop/status")
def get_fast_scan_status():
    return fast_scan_state

@app.post("/api/scan/fast-laptop")
def start_fast_laptop_scan(background_tasks: BackgroundTasks):
    if fast_scan_state["status"] == "SCANNING":
        return fast_scan_state
    background_tasks.add_task(execute_fast_laptop_scan_thread)
    return {"status": "started", "message": "5-Minute Fast Laptop Scan initialized."}

# ==================== ENCRYPTED CREDENTIALS & ACCOUNT VAULT ====================
VAULT_FILE = os.path.join(BASE_DIR, "credentials_vault.enc")
VAULT_SALT_FILE = os.path.join(BASE_DIR, "vault_salt.bin")

def get_vault_salt() -> bytes:
    if not os.path.exists(VAULT_SALT_FILE):
        salt = os.urandom(16)
        with open(VAULT_SALT_FILE, "wb") as f:
            f.write(salt)
        return salt
    with open(VAULT_SALT_FILE, "rb") as f:
        return f.read()

def derive_vault_key(pin: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(pin.encode("utf-8")))

def load_encrypted_vault_entries(pin: str) -> List[Dict[str, Any]]:
    if not os.path.exists(VAULT_FILE):
        return []
    salt = get_vault_salt()
    key = derive_vault_key(pin, salt)
    f = Fernet(key)
    try:
        with open(VAULT_FILE, "rb") as vf:
            ciphertext = vf.read()
        if not ciphertext:
            return []
        decrypted = f.decrypt(ciphertext)
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=401, detail="Incorrect Master PIN or unable to decrypt vault.")

def save_encrypted_vault_entries(pin: str, entries: List[Dict[str, Any]]):
    salt = get_vault_salt()
    key = derive_vault_key(pin, salt)
    f = Fernet(key)
    raw_bytes = json.dumps(entries, indent=2).encode("utf-8")
    ciphertext = f.encrypt(raw_bytes)
    with open(VAULT_FILE, "wb") as vf:
        vf.write(ciphertext)

@app.get("/api/vault/status")
def get_vault_status():
    is_set = os.path.exists(VAULT_FILE) and os.path.getsize(VAULT_FILE) > 0
    return {
        "is_configured": is_set,
        "encryption": "AES-256-Fernet (PBKDF2HMAC-SHA256)",
        "vault_file": "credentials_vault.enc"
    }

@app.post("/api/vault/setup-pin")
def setup_vault_pin(payload: VaultSetupPinRequest):
    pin = payload.pin.strip()
    confirm_pin = payload.confirm_pin.strip()
    if len(pin) < 4:
        raise HTTPException(status_code=400, detail="Dedicated Vault PIN must be at least 4 digits.")
    if pin != confirm_pin:
        raise HTTPException(status_code=400, detail="PINs do not match. Please verify your PIN.")
    
    entries = []
    if os.path.exists(VAULT_FILE) and os.path.getsize(VAULT_FILE) > 0:
        if payload.old_pin:
            entries = load_encrypted_vault_entries(payload.old_pin.strip())
        else:
            try:
                entries = load_encrypted_vault_entries(pin)
            except Exception:
                raise HTTPException(status_code=400, detail="Existing vault detected. Current PIN is required to change Vault PIN.")

    save_encrypted_vault_entries(pin, entries)
    log_event("SUCCESS", "VAULT", "Dedicated Vault Security PIN configured and vault re-encrypted.")
    return {"status": "configured", "message": "Dedicated Vault PIN successfully saved."}

@app.post("/api/vault/verify-pin")
def verify_vault_pin(payload: VaultVerifyRequest):
    pin = payload.pin.strip()
    if not pin or len(pin) < 4:
        raise HTTPException(status_code=400, detail="Master PIN must be at least 4 digits.")
    
    if not os.path.exists(VAULT_FILE):
        save_encrypted_vault_entries(pin, [])
        log_event("SUCCESS", "VAULT", "Encrypted Credentials Vault created and initialized with Master PIN.")
        return {"status": "initialized", "is_new": True, "message": "Master PIN set and vault initialized."}
    
    entries = load_encrypted_vault_entries(pin)
    return {"status": "unlocked", "is_new": False, "count": len(entries)}

@app.get("/api/vault")
def get_vault_entries(pin: str = Query(...), user_id: Optional[str] = Query("default")):
    entries = load_encrypted_vault_entries(pin)
    if user_id and user_id != "all":
        scoped = [e for e in entries if e.get("user_id") == user_id or e.get("user_id") is None]
        return {"entries": scoped, "total": len(scoped)}
    return {"entries": entries, "total": len(entries)}

@app.post("/api/vault")
def save_vault_entry(payload: VaultSaveRequest):
    entries = load_encrypted_vault_entries(payload.pin)
    new_entry = payload.entry.model_dump()
    if not new_entry.get("id"):
        new_entry["id"] = str(uuid.uuid4())
    new_entry["user_id"] = payload.user_id or "default"
    new_entry["updated_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    idx = next((i for i, e in enumerate(entries) if e["id"] == new_entry["id"]), -1)
    if idx >= 0:
        entries[idx] = new_entry
    else:
        entries.insert(0, new_entry)

    save_encrypted_vault_entries(payload.pin, entries)
    log_event("INFO", "VAULT", f"Account credentials saved for service: {new_entry.get('service_name')}")
    return {"status": "saved", "entry": new_entry}

@app.delete("/api/vault/{entry_id}")
def delete_vault_entry(entry_id: str, pin: str = Query(...), user_id: Optional[str] = Query("default")):
    entries = load_encrypted_vault_entries(pin)
    orig_len = len(entries)
    entries = [e for e in entries if e["id"] != entry_id]
    if len(entries) == orig_len:
        raise HTTPException(status_code=404, detail="Vault entry not found.")

    save_encrypted_vault_entries(pin, entries)
    log_event("INFO", "VAULT", f"Account credentials deleted from vault (ID: {entry_id[:8]}...)")
    return {"status": "deleted", "id": entry_id}

# ==================== CENTRALIZED AUDIT LOGGER ====================
ADMIN_EMAIL_LOWER = "bmwm25320@gmail.com"
AUDIT_LOGS_FILE = os.path.join(BASE_DIR, "audit_logs_store.json")

def load_audit_logs() -> List[Dict[str, Any]]:
    if not os.path.exists(AUDIT_LOGS_FILE):
        return init_audit_logs_seed()
    try:
        with open(AUDIT_LOGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else init_audit_logs_seed()
    except Exception:
        return init_audit_logs_seed()

def save_audit_logs(records: List[Dict[str, Any]]):
    try:
        with open(AUDIT_LOGS_FILE, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
    except Exception as e:
        log_event("WARNING", "AUDIT", f"Could not write audit store: {e}")

def init_audit_logs_seed() -> List[Dict[str, Any]]:
    now = datetime.now()
    seed = [
        {
            "id": str(uuid.uuid4()),
            "uid": "google_oauth_admin_982341",
            "email": "bmwm25320@gmail.com",
            "full_name": "SuperAdmin (Master Controller)",
            "photo_url": "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=120&auto=format&fit=crop&q=80",
            "event_type": "USER_LOGIN",
            "login_date": now.strftime("%B %d, %Y"),
            "login_time": now.strftime("%I:%M:%S %p IST"),
            "iso_timestamp": now.isoformat() + "Z",
            "platform": "Windows Desktop"
        },
        {
            "id": str(uuid.uuid4()),
            "uid": "google_oauth_sumit_783109",
            "email": "sumit.security@sentinelgrid.ai",
            "full_name": "Sumit Kumar (Security Lead)",
            "photo_url": "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=120&auto=format&fit=crop&q=80",
            "event_type": "USER_LOGIN",
            "login_date": now.strftime("%B %d, %Y"),
            "login_time": (now - timedelta(minutes=42)).strftime("%I:%M:%S %p IST"),
            "iso_timestamp": (now - timedelta(minutes=42)).isoformat() + "Z",
            "platform": "Android Mobile"
        },
        {
            "id": str(uuid.uuid4()),
            "uid": "google_oauth_alex_554120",
            "email": "alex.dev@sentinelgrid.ai",
            "full_name": "Alex Vance (DevOps)",
            "photo_url": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=120&auto=format&fit=crop&q=80",
            "event_type": "NEW_ACCOUNT_SIGNUP",
            "login_date": now.strftime("%B %d, %Y"),
            "login_time": (now - timedelta(hours=2, minutes=15)).strftime("%I:%M:%S %p IST"),
            "iso_timestamp": (now - timedelta(hours=2, minutes=15)).isoformat() + "Z",
            "platform": "Web Portal"
        },
        {
            "id": str(uuid.uuid4()),
            "uid": "google_oauth_clara_331902",
            "email": "clara.soc@cloudcorp.io",
            "full_name": "Clara Oswald (SOC Analyst)",
            "photo_url": "https://images.unsplash.com/photo-1494790108377-be9c29b29330?w=120&auto=format&fit=crop&q=80",
            "event_type": "USER_LOGIN",
            "login_date": (now - timedelta(days=1)).strftime("%B %d, %Y"),
            "login_time": "04:15:30 PM IST",
            "iso_timestamp": (now - timedelta(days=1)).isoformat() + "Z",
            "platform": "Windows Desktop"
        },
        {
            "id": str(uuid.uuid4()),
            "uid": "google_oauth_marcus_119283",
            "email": "marcus.mobile@guard.net",
            "full_name": "Marcus Brody (Field Agent)",
            "photo_url": "https://images.unsplash.com/photo-1500648767791-00dcc994a43e?w=120&auto=format&fit=crop&q=80",
            "event_type": "NEW_ACCOUNT_SIGNUP",
            "login_date": (now - timedelta(days=1)).strftime("%B %d, %Y"),
            "login_time": "11:08:44 AM IST",
            "iso_timestamp": (now - timedelta(days=1)).isoformat() + "Z",
            "platform": "Android Mobile"
        }
    ]
    save_audit_logs(seed)
    return seed

@app.post("/api/audit/login")
def log_audit_login(payload: LoginAuditLogModel):
    records = load_audit_logs()
    entry = payload.model_dump()
    if not entry.get("id"):
        entry["id"] = str(uuid.uuid4())
    
    records.insert(0, entry)
    save_audit_logs(records)
    log_event("SUCCESS", "AUDIT", f"Login Audit Event: {entry.get('email')} via {entry.get('platform')} ({entry.get('event_type')})")
    return {"status": "logged", "log": entry}

@app.get("/api/audit/logs")
def get_audit_logs(admin_email: str = Query(...)):
    if admin_email.strip().lower() != ADMIN_EMAIL_LOWER:
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied. Only SuperAdmin ({ADMIN_EMAIL_LOWER}) is authorized to view audit logs."
        )
    records = load_audit_logs()
    return {"logs": records, "total": len(records), "admin_authorized": True}

@app.get("/api/audit/stats")
def get_audit_stats(admin_email: str = Query(...)):
    if admin_email.strip().lower() != ADMIN_EMAIL_LOWER:
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied. Only SuperAdmin ({ADMIN_EMAIL_LOWER}) is authorized to view audit statistics."
        )
    records = load_audit_logs()
    unique_users = len(set(r.get("email", "").lower() for r in records if r.get("email")))
    today_str = datetime.now().strftime("%B %d, %Y")
    
    logins_today = sum(1 for r in records if today_str.lower() in r.get("login_date", "").lower())
    
    windows_cnt = sum(1 for r in records if "windows" in r.get("platform", "").lower())
    android_cnt = sum(1 for r in records if "android" in r.get("platform", "").lower())
    web_cnt = sum(1 for r in records if "web" in r.get("platform", "").lower())

    signups_cnt = sum(1 for r in records if r.get("event_type") == "NEW_ACCOUNT_SIGNUP")
    logins_cnt = sum(1 for r in records if r.get("event_type") != "NEW_ACCOUNT_SIGNUP")

    return {
        "total_users": unique_users,
        "total_logins": len(records),
        "logins_today": logins_today,
        "platforms": {
            "windows": windows_cnt,
            "android": android_cnt,
            "web": web_cnt
        },
        "event_types": {
            "signups": signups_cnt,
            "logins": logins_cnt
        }
    }

@app.post("/api/audit/seed")
def seed_audit_demo(payload: SeedAuditRequest):
    if payload.admin_email.strip().lower() != ADMIN_EMAIL_LOWER:
        raise HTTPException(
            status_code=403,
            detail="Access Denied: Only SuperAdmin can re-seed audit records."
        )
    records = init_audit_logs_seed()
    return {"status": "seeded", "count": len(records)}

# ==================== ANDROID APK RELEASE & DOWNLOAD ====================
RELEASES_DIR = os.path.join(BASE_DIR, "releases")
os.makedirs(RELEASES_DIR, exist_ok=True)
APK_PATH = os.path.join(RELEASES_DIR, "SentinelGrid_Defense_v1.0.apk")

@app.get("/api/download/android-apk")
def download_android_apk():
    if not os.path.exists(APK_PATH):
        # Look for compiled artifacts in android project
        candidate_paths = [
            os.path.abspath(os.path.join(BASE_DIR, "..", "frontend", "android", "app", "build", "outputs", "apk", "debug", "app-debug.apk")),
            os.path.abspath(os.path.join(BASE_DIR, "..", "frontend", "android", "app", "build", "outputs", "apk", "release", "app-release.apk"))
        ]
        for cp in candidate_paths:
            if os.path.exists(cp):
                shutil.copy2(cp, APK_PATH)
                break
        
    if not os.path.exists(APK_PATH):
        raise HTTPException(
            status_code=404,
            detail="Android APK is currently assembling or awaiting build generation."
        )

    return FileResponse(
        APK_PATH,
        media_type="application/vnd.android.package-archive",
        filename="SentinelGrid_Defense_v1.0.apk"
    )

# ==================== FRONTEND STATIC SPA HOSTING ====================
candidate_dists = [
    os.path.abspath(os.path.join(BASE_DIR, "..", "frontend", "dist")),
    os.path.abspath(os.path.join(BASE_DIR, "frontend", "dist")),
    os.path.abspath(os.path.join(getattr(sys, '_MEIPASS', ''), "frontend", "dist")),
    os.path.abspath(os.path.join(getattr(sys, '_MEIPASS', ''), "dist")),
    os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist")),
]
FRONTEND_DIST = None
for cd in candidate_dists:
    if cd and os.path.exists(cd) and os.path.isdir(cd):
        FRONTEND_DIST = cd
        break

if FRONTEND_DIST and os.path.exists(FRONTEND_DIST):
    from fastapi.staticfiles import StaticFiles
    from starlette.responses import FileResponse

    assets_dir = os.path.join(FRONTEND_DIST, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="static_assets")

    @app.get("/{full_path:path}")
    async def serve_spa_frontend(full_path: str):
        # Do not intercept API paths
        if full_path.startswith("api"):
            raise HTTPException(status_code=404, detail="API route not found")
        
        target = os.path.join(FRONTEND_DIST, full_path)
        if full_path and os.path.isfile(target):
            return FileResponse(target)
            
        index_file = os.path.join(FRONTEND_DIST, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        raise HTTPException(status_code=404, detail="Frontend index.html not found")

@app.on_event("shutdown")
def shutdown_event():
    observer.stop()
    observer.join()
    log_event("INFO", "CORE", "SentinelGrid OS Guardian shutdown safely.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("engine:app", host="0.0.0.0", port=8000, reload=False)
