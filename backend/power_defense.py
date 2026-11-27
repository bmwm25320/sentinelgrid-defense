"""
SentinelGrid Defense - Advanced Active Defense Layer (Windows Power Suite)
1. Behavioral LOLBin & Parent-Child Process Threat Hunter
2. Scheduled Tasks Persistence Scanner
3. System-Wide DNS / HOSTS Phishing & Malware Domain Shield
4. Immutable Ransomware Snapshot Backup Vault
"""
import os
import re
import io
import csv
import time
import zipfile
import platform
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any

import psutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROTECTED_ZONE_DIR = os.path.join(BASE_DIR, "protected_zone")
BACKUPS_DIR = os.path.join(BASE_DIR, "safe_backups")
HOSTS_STATE_FILE = os.path.join(BASE_DIR, "dns_shield_state.json")

_SENTINEL_MARKER_START = "# >>> SENTINELGRID DNS SHIELD START"
_SENTINEL_MARKER_END = "# <<< SENTINELGRID DNS SHIELD END"

# Curated high-confidence phishing, malware drop, and C2 blocklist domains
BLOCKED_MALWARE_DOMAINS = [
    "paypal-login-security-alert.tk",
    "secure-login-verify-update.xyz",
    "microsoft-support-alert-fix.top",
    "sbi-kyc-update-alert.xyz",
    "hdfc-pan-verify-now.click",
    "evil-c2-dropper.tk",
    "free-nitro-claim-gift.buzz",
    "metamask-recovery-seed-sync.top",
    "fedex-parcel-customs-fee.xyz",
    "apk-mod-cracked-loader.gq",
    "windows-defender-activate.cf",
    "telemetry-tracker-collect.ml",
]

_LOLBIN_RULES = [
    (re.compile(r"powershell.*(-enc|-encodedcommand|frombase64string|invoke-expression|\biex\b|downloadstring|net\.webclient)", re.I),
     "T1059.001", "Encoded/Remote PowerShell Execution", 85),
    (re.compile(r"certutil.*(-urlcache|-decode|-split)", re.I),
     "T1105", "Certutil Ingress Tool Transfer", 80),
    (re.compile(r"mshta.*(http://|https://|javascript:|vbscript:)", re.I),
     "T1218.005", "Mshta Remote Script Execution", 85),
    (re.compile(r"bitsadmin.*(/transfer|/addfile)", re.I),
     "T1197", "BITS Jobs Payload Transfer", 75),
    (re.compile(r"regsvr32.*(/i:http|/u\s+/n)", re.I),
     "T1218.010", "Regsvr32 Proxy Execution (Squiblydoo)", 85),
    (re.compile(r"(xmrig|minerd|nicehash|coinhive|stratum\+tcp)", re.I),
     "T1496", "Unauthorized Crypto-Miner Indicator", 90),
]

_OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "acrobat.exe"}
_SCRIPT_CHILDREN = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe"}
_TRUSTED_DEV_KEYWORDS = ("vscode", "antigravity", "python", "node", "uvicorn", "sentinelgrid", "google", "microsoft")


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _subprocess_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if _is_windows() else 0


# ==================== 1. BEHAVIORAL PROCESS & LOLBIN HUNTER ====================

def evaluate_command_line_risk(
    proc_name: str,
    exe_path: str,
    cmdline_str: str,
    parent_name: str = "",
) -> Dict[str, Any]:
    """Evaluates a single process command line & parent-child chain for LOLBin abuse."""
    pname_low = (proc_name or "").lower()
    exe_low = (exe_path or "").lower()
    cmd_low = (cmdline_str or "").lower()
    parent_low = (parent_name or "").lower()

    reasons: List[str] = []
    mitre_id = "T1059"
    risk_score = 0

    for pattern, mid, label, weight in _LOLBIN_RULES:
        if pattern.search(cmd_low):
            risk_score = max(risk_score, weight)
            mitre_id = mid
            reasons.append(f"{label} ({mid})")

    if parent_low in _OFFICE_PARENTS and pname_low in _SCRIPT_CHILDREN:
        risk_score = max(risk_score, 85)
        mitre_id = "T1566.001"
        reasons.append(f"Suspicious Office/PDF macro spawn: {parent_name} -> {proc_name}")

    is_temp_exec = any(seg in exe_low for seg in ("\\temp\\", "\\users\\public\\", "\\programdata\\"))
    is_dev_trusted = any(k in exe_low or k in cmd_low for k in _TRUSTED_DEV_KEYWORDS)
    if is_temp_exec and not is_dev_trusted:
        risk_score = max(risk_score, 60)
        if mitre_id == "T1059":
            mitre_id = "T1204"
        reasons.append(f"Untrusted binary running directly from temporary/public folder: {exe_path}")

    severity = "CRITICAL" if risk_score >= 80 else ("HIGH" if risk_score >= 60 else ("MEDIUM" if risk_score >= 35 else "SAFE"))
    return {
        "risk_score": risk_score,
        "severity": severity,
        "mitre_id": mitre_id,
        "reasons": reasons,
    }


def hunt_behavioral_threats() -> Dict[str, Any]:
    """Hunts live OS processes for LOLBins, encoded commands, and suspicious Office spawns."""
    inspected = 0
    threats: List[Dict[str, Any]] = []
    self_pid = os.getpid()

    pid_names: Dict[int, str] = {}
    proc_snapshots: List[Dict[str, Any]] = []

    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username"]):
        try:
            info = proc.info
            pid = int(info.get("pid") or 0)
            name = str(info.get("name") or "")
            pid_names[pid] = name
            proc_snapshots.append(info)
        except Exception:
            continue

    for info in proc_snapshots:
        pid = int(info.get("pid") or 0)
        if pid <= 4 or pid == self_pid:
            continue
        inspected += 1
        name = str(info.get("name") or "")
        exe = str(info.get("exe") or "")
        cmd_list = info.get("cmdline") or []
        cmdline = " ".join(str(x) for x in cmd_list) if isinstance(cmd_list, list) else str(cmd_list)
        ppid = int(info.get("ppid") or 0)
        parent_name = pid_names.get(ppid, "")

        # Skip SentinelGrid backend / own test runner python scripts
        if "sentinelgrid" in cmdline.lower() or "test_active_defense" in cmdline.lower():
            continue

        ev = evaluate_command_line_risk(name, exe, cmdline, parent_name)
        if ev["risk_score"] >= 55:
            threats.append({
                "pid": pid,
                "ppid": ppid,
                "parent_name": parent_name or "Unknown",
                "name": name,
                "exe": exe or "N/A",
                "cmdline": cmdline[:240],
                "risk_score": ev["risk_score"],
                "severity": ev["severity"],
                "mitre_id": ev["mitre_id"],
                "reasons": ev["reasons"],
            })

    threats.sort(key=lambda t: t["risk_score"], reverse=True)
    return {
        "status": "ALERT" if threats else "CLEAN",
        "processes_inspected": inspected,
        "threats_found": len(threats),
        "threats": threats[:20],
        "scanned_at": datetime.now().strftime("%H:%M:%S"),
    }


# ==================== 2. SCHEDULED TASKS PERSISTENCE SCANNER ====================

def parse_schtasks_csv(csv_text: str) -> List[Dict[str, Any]]:
    """Parses `schtasks /query /fo CSV /v` stdout and flags suspicious persistence tasks."""
    flagged: List[Dict[str, Any]] = []
    if not csv_text or not csv_text.strip():
        return flagged

    reader = csv.DictReader(io.StringIO(csv_text))
    seen_names = set()
    for row in reader:
        task_name = (row.get("TaskName") or "").strip()
        cmd = (row.get("Task To Run") or "").strip()
        author = (row.get("Author") or "").strip()
        if not task_name or task_name == "TaskName" or task_name in seen_names:
            continue
        seen_names.add(task_name)

        low_cmd = cmd.lower()
        low_name = task_name.lower()
        # Ignore official Microsoft system paths unless running suspicious scripts
        is_suspicious = (
            "-enc" in low_cmd
            or "frombase64string" in low_cmd
            or "\\temp\\" in low_cmd
            or "\\users\\public\\" in low_cmd
            or ("mshta" in low_cmd and "http" in low_cmd)
            or (".vbs" in low_cmd and not low_name.startswith("\\microsoft\\"))
            or (".bat" in low_cmd and "\\appdata\\roaming\\" in low_cmd)
        )
        if is_suspicious:
            flagged.append({
                "task_name": task_name,
                "command": cmd[:220],
                "author": author or "Unknown",
                "status": (row.get("Status") or "Ready").strip(),
                "severity": "HIGH",
            })
    return flagged[:25]


def scan_scheduled_tasks_persistence() -> Dict[str, Any]:
    if not _is_windows():
        return {"supported": False, "suspicious_count": 0, "tasks": [], "scanned_at": datetime.now().strftime("%H:%M:%S")}

    try:
        res = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore",
            timeout=25, creationflags=_subprocess_flags(),
        )
        tasks = parse_schtasks_csv(res.stdout or "")
        return {
            "supported": True,
            "suspicious_count": len(tasks),
            "tasks": tasks,
            "scanned_at": datetime.now().strftime("%H:%M:%S"),
        }
    except Exception as exc:
        return {"supported": False, "suspicious_count": 0, "tasks": [], "error": str(exc), "scanned_at": datetime.now().strftime("%H:%M:%S")}


# ==================== 3. DNS / HOSTS PHISHING & MALWARE SHIELD ====================

def _windows_hosts_path() -> str:
    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    return os.path.join(sys_root, "System32", "drivers", "etc", "hosts")


def get_dns_shield_status() -> Dict[str, Any]:
    import json
    enabled_soft = False
    hosts_enforced = False

    if os.path.exists(HOSTS_STATE_FILE):
        try:
            with open(HOSTS_STATE_FILE, "r", encoding="utf-8") as f:
                st = json.load(f)
                enabled_soft = bool(st.get("enabled", False))
        except Exception:
            pass

    if _is_windows() and os.path.exists(_windows_hosts_path()):
        try:
            with open(_windows_hosts_path(), "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                if _SENTINEL_MARKER_START in content:
                    hosts_enforced = True
                    enabled_soft = True
        except Exception:
            pass

    return {
        "enabled": enabled_soft or hosts_enforced,
        "hosts_enforced": hosts_enforced,
        "domains_count": len(BLOCKED_MALWARE_DOMAINS),
        "sample_domains": BLOCKED_MALWARE_DOMAINS[:5],
    }


def set_dns_shield(enabled: bool) -> Dict[str, Any]:
    import json
    hosts_enforced = False
    note = "Software DNS Phishing Blocklist enabled." if enabled else "DNS Shield paused."

    if _is_windows() and os.path.exists(_windows_hosts_path()):
        try:
            with open(_windows_hosts_path(), "r", encoding="utf-8", errors="ignore") as f:
                raw = f.read()

            # Strip any existing SentinelGrid block cleanly
            cleaned = re.sub(
                rf"\r?\n?{re.escape(_SENTINEL_MARKER_START)}[\s\S]*?{re.escape(_SENTINEL_MARKER_END)}\r?\n?",
                "\n",
                raw,
            ).rstrip()

            if enabled:
                entries = "\n".join(f"0.0.0.0 {dom}" for dom in BLOCKED_MALWARE_DOMAINS)
                new_body = f"{cleaned}\n\n{_SENTINEL_MARKER_START}\n{entries}\n{_SENTINEL_MARKER_END}\n"
            else:
                new_body = cleaned + "\n"

            with open(_windows_hosts_path(), "w", encoding="utf-8") as f:
                f.write(new_body)
            hosts_enforced = enabled
            note = (
                f"Blocked {len(BLOCKED_MALWARE_DOMAINS)} malware/phishing domains in Windows HOSTS file."
                if enabled else "Removed SentinelGrid DNS block entries from Windows HOSTS file."
            )
        except PermissionError:
            note = (
                f"Active in Web/URL Shield ({len(BLOCKED_MALWARE_DOMAINS)} domains); run as Administrator to enforce OS-wide HOSTS lock."
                if enabled else "DNS Shield disabled."
            )
        except Exception as exc:
            note = f"Software Shield updated ({exc})."

    try:
        with open(HOSTS_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({"enabled": enabled, "updated_at": datetime.now().isoformat()}, f)
    except Exception:
        pass

    return {
        "enabled": enabled,
        "hosts_enforced": hosts_enforced,
        "domains_count": len(BLOCKED_MALWARE_DOMAINS),
        "note": note,
    }


def is_domain_blocked_by_dns_shield(domain: str) -> bool:
    dom = (domain or "").lower().strip()
    if not dom:
        return False
    st = get_dns_shield_status()
    if not st["enabled"]:
        return False
    return any(dom == b or dom.endswith("." + b) for b in BLOCKED_MALWARE_DOMAINS)


# ==================== 4. IMMUTABLE RANSOMWARE SNAPSHOT BACKUP ====================

def create_protected_snapshot_backup() -> Dict[str, Any]:
    os.makedirs(BACKUPS_DIR, exist_ok=True)
    os.makedirs(PROTECTED_ZONE_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name = f"sg_protected_backup_{ts}.zip"
    zip_path = os.path.join(BACKUPS_DIR, zip_name)

    files_backed = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(PROTECTED_ZONE_DIR):
            for fname in files:
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, PROTECTED_ZONE_DIR)
                zf.write(fpath, arcname=rel)
                files_backed += 1

    # Retain latest 8 snapshots automatically to save disk space
    all_zips = sorted(
        [f for f in os.listdir(BACKUPS_DIR) if f.endswith(".zip")],
        reverse=True,
    )
    for old_zip in all_zips[8:]:
        try:
            os.remove(os.path.join(BACKUPS_DIR, old_zip))
        except Exception:
            pass

    size_kb = round(os.path.getsize(zip_path) / 1024.0, 2)
    return {
        "status": "backed_up",
        "snapshot_name": zip_name,
        "files_backed_up": files_backed,
        "size_kb": size_kb,
        "created_at": datetime.now().strftime("%H:%M:%S"),
    }


def list_snapshot_backups() -> List[Dict[str, Any]]:
    if not os.path.exists(BACKUPS_DIR):
        return []
    snaps = []
    for fname in sorted(os.listdir(BACKUPS_DIR), reverse=True):
        if not fname.endswith(".zip"):
            continue
        fpath = os.path.join(BACKUPS_DIR, fname)
        snaps.append({
            "name": fname,
            "size_kb": round(os.path.getsize(fpath) / 1024.0, 2),
        })
    return snaps[:10]
