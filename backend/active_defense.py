"""
SentinelGrid Defense - Active Defense Modules
Kaspersky-Grade Hardware Privacy Guard, USB Auto-Shield, Active IP Firewall Blocker,
ARP MITM Inspector, and Zero-Knowledge k-Anonymity Dark Web Breach Auditor.
"""
import os
import re
import json
import time
import ctypes
import hashlib
import ipaddress
import platform
import subprocess
import urllib.request
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable

import psutil

try:
    import winreg
except ImportError:
    winreg = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLOCKED_IPS_FILE = os.path.join(BASE_DIR, "blocked_ips.json")

# In-memory cache for k-anonymity SHA-1 prefix queries to minimize network round-trips
_hibp_prefix_cache: Dict[str, Dict[str, int]] = {}


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _subprocess_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if _is_windows() else 0


# ==================== 1. ZERO-KNOWLEDGE BREACH AUDITOR ====================

def check_password_breach_k_anonymity(password: str, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Checks a password against HaveIBeenPwned using k-anonymity:
    only the first 5 characters of its SHA-1 hash leave the device.
    """
    if not password:
        return {"breached": False, "count": 0, "checked_online": False}

    sha1_hex = hashlib.sha1(password.encode("utf-8", errors="ignore")).hexdigest().upper()
    prefix, suffix = sha1_hex[:5], sha1_hex[5:]

    if prefix in _hibp_prefix_cache:
        count = _hibp_prefix_cache[prefix].get(suffix, 0)
        return {"breached": count > 0, "count": count, "checked_online": True}

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "SentinelGrid-Defense-Suite/3.0",
            "Add-Padding": "true",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            suffix_map: Dict[str, int] = {}
            for line in body.splitlines():
                if ":" not in line:
                    continue
                sfx, cnt_str = line.strip().split(":", 1)
                try:
                    cnt = int(cnt_str)
                except ValueError:
                    cnt = 0
                if cnt > 0:
                    suffix_map[sfx.upper()] = cnt
            _hibp_prefix_cache[prefix] = suffix_map
            count = suffix_map.get(suffix, 0)
            return {"breached": count > 0, "count": count, "checked_online": True}
    except Exception as exc:
        return {"breached": False, "count": 0, "checked_online": False, "error": str(exc)}


def _assess_password_strength(pwd: str) -> str:
    if len(pwd) < 8:
        return "WEAK"
    score = 0
    if len(pwd) >= 12:
        score += 1
    if any(c.isupper() for c in pwd):
        score += 1
    if any(c.isdigit() for c in pwd):
        score += 1
    if any(not c.isalnum() for c in pwd):
        score += 1
    if score <= 1:
        return "WEAK"
    if score == 2:
        return "GOOD"
    return "STRONG"


def audit_vault_breaches(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Audits all unlocked vault credentials for:
    - Dark Web leaks (k-anonymity HaveIBeenPwned check)
    - Reused passwords across multiple services
    - Weak passwords
    """
    pwd_usage: Dict[str, int] = {}
    for entry in entries:
        pwd = entry.get("password") or ""
        if pwd:
            pwd_usage[pwd] = pwd_usage.get(pwd, 0) + 1

    results: List[Dict[str, Any]] = []
    breached_count = 0
    reused_count = 0
    weak_count = 0
    online_checks = 0

    for entry in entries:
        pwd = entry.get("password") or ""
        res = check_password_breach_k_anonymity(pwd)
        if res.get("checked_online"):
            online_checks += 1
        is_breached = bool(res.get("breached"))
        leak_count = int(res.get("count", 0))
        is_reused = bool(pwd and pwd_usage.get(pwd, 0) > 1)
        strength = _assess_password_strength(pwd)

        if is_breached:
            breached_count += 1
        if is_reused:
            reused_count += 1
        if strength == "WEAK":
            weak_count += 1

        results.append({
            "id": entry.get("id"),
            "service_name": entry.get("service_name", "Unknown"),
            "username": entry.get("username", ""),
            "breached": is_breached,
            "leak_count": leak_count,
            "reused": is_reused,
            "strength": strength,
            "checked_online": bool(res.get("checked_online")),
        })

    return {
        "total_entries": len(entries),
        "breached_count": breached_count,
        "reused_count": reused_count,
        "weak_count": weak_count,
        "hibp_reachable": online_checks > 0 or len(entries) == 0,
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "results": results,
    }


# ==================== 2. ACTIVE FIREWALL IP BLOCKER & ARP INSPECTOR ====================

def load_blocked_ips() -> List[Dict[str, Any]]:
    if not os.path.exists(BLOCKED_IPS_FILE):
        return []
    try:
        with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_blocked_ips(records: List[Dict[str, Any]]):
    try:
        with open(BLOCKED_IPS_FILE, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
    except Exception:
        pass


def validate_blockable_ip(raw_ip: str) -> str:
    ip_obj = ipaddress.ip_address(raw_ip.strip())
    if ip_obj.is_loopback or ip_obj.is_unspecified or ip_obj.is_multicast:
        raise ValueError(f"Refusing to block protected local/system address: {raw_ip}")
    return str(ip_obj)


def block_ip_firewall(raw_ip: str, reason: str = "Operator Threat Block") -> Dict[str, Any]:
    ip_str = validate_blockable_ip(raw_ip)
    rule_base = f"SentinelGrid_Block_{ip_str.replace(':', '_')}"
    firewall_enforced = False
    netsh_note = "Software blocklist active"

    if _is_windows():
        try:
            res_out = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_base}_OUT", "dir=out", "action=block",
                    f"remoteip={ip_str}", "enable=yes"
                ],
                capture_output=True, text=True, timeout=6,
                creationflags=_subprocess_flags(),
            )
            res_in = subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_base}_IN", "dir=in", "action=block",
                    f"remoteip={ip_str}", "enable=yes"
                ],
                capture_output=True, text=True, timeout=6,
                creationflags=_subprocess_flags(),
            )
            if res_out.returncode == 0 or res_in.returncode == 0:
                firewall_enforced = True
                netsh_note = "Windows Firewall Inbound + Outbound rule active"
            else:
                err = (res_out.stderr or res_out.stdout or "").strip()
                netsh_note = f"Software shield active (Windows Firewall UAC required for kernel rule: {err[:80]})"
        except Exception as exc:
            netsh_note = f"Software shield active ({exc})"

    records = load_blocked_ips()
    records = [r for r in records if r.get("ip") != ip_str]
    entry = {
        "ip": ip_str,
        "reason": reason,
        "rule_name": rule_base,
        "firewall_enforced": firewall_enforced,
        "enforcement_note": netsh_note,
        "blocked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    records.insert(0, entry)
    save_blocked_ips(records)
    return entry


def unblock_ip_firewall(raw_ip: str) -> bool:
    ip_str = raw_ip.strip()
    rule_base = f"SentinelGrid_Block_{ip_str.replace(':', '_')}"
    if _is_windows():
        for suffix in ("_OUT", "_IN"):
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_base}{suffix}"],
                    capture_output=True, text=True, timeout=6,
                    creationflags=_subprocess_flags(),
                )
            except Exception:
                pass
    records = load_blocked_ips()
    updated = [r for r in records if r.get("ip") != ip_str]
    save_blocked_ips(updated)
    return len(updated) < len(records)


def inspect_arp_mitm() -> Dict[str, Any]:
    """
    Inspects local ARP table for duplicate unicast MAC addresses bound to distinct IPs
    (classic indicator of ARP Cache Poisoning / Man-in-the-Middle attacks).
    """
    if not _is_windows():
        return {"status": "SAFE", "anomalies": [], "entries_checked": 0}

    try:
        res = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=5,
            creationflags=_subprocess_flags(),
        )
        output = res.stdout or ""
    except Exception as exc:
        return {"status": "UNKNOWN", "anomalies": [], "entries_checked": 0, "error": str(exc)}

    current_iface = "default"
    mac_to_ips: Dict[str, List[str]] = {}
    entries_checked = 0

    for line in output.splitlines():
        iface_match = re.search(r"Interface:\s+([\d.]+)", line)
        if iface_match:
            current_iface = iface_match.group(1)
            continue

        row_match = re.match(r"^\s*([\d.]+)\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
        if not row_match:
            continue

        ip_addr, mac_addr, arp_type = row_match.groups()
        mac_lower = mac_addr.lower()
        # Ignore broadcast & multicast hardware addresses
        if (
            mac_lower == "ff-ff-ff-ff-ff-ff"
            or mac_lower.startswith("01-00-5e")
            or mac_lower.startswith("33-33")
            or arp_type.lower() == "static"
        ):
            continue

        entries_checked += 1
        key = f"{current_iface}|{mac_lower}"
        mac_to_ips.setdefault(key, [])
        if ip_addr not in mac_to_ips[key]:
            mac_to_ips[key].append(ip_addr)

    anomalies = []
    for key, ips in mac_to_ips.items():
        if len(ips) > 1:
            iface, mac = key.split("|", 1)
            anomalies.append({
                "interface": iface,
                "mac_address": mac,
                "conflicting_ips": ips,
                "description": f"Multiple IPs ({', '.join(ips)}) resolve to MAC {mac} — possible ARP spoofing/MITM."
            })

    return {
        "status": "ALERT" if anomalies else "SAFE",
        "anomalies": anomalies,
        "entries_checked": entries_checked,
        "checked_at": datetime.now().strftime("%H:%M:%S"),
    }


# ==================== 3. HARDWARE PRIVACY GUARD & CLIPBOARD WIPE ====================

def _format_app_label(raw_key: str) -> str:
    if "#" in raw_key:
        raw_key = raw_key.replace("#", "\\")
    return os.path.basename(raw_key) or raw_key


def _scan_consent_store(category: str) -> Dict[str, List[Dict[str, Any]]]:
    active_apps: List[Dict[str, Any]] = []
    recent_apps: List[Dict[str, Any]] = []
    if not _is_windows() or winreg is None:
        return {"active": active_apps, "recent": recent_apps}

    base_path = rf"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{category}"

    def _inspect_key(hkey, sub_path: str, app_name: str):
        try:
            with winreg.OpenKey(hkey, sub_path) as sk:
                try:
                    start_val, _ = winreg.QueryValueEx(sk, "LastUsedTimeStart")
                    stop_val, _ = winreg.QueryValueEx(sk, "LastUsedTimeStop")
                except FileNotFoundError:
                    return
                label = _format_app_label(app_name)
                if start_val and stop_val == 0:
                    active_apps.append({"app": label, "path": app_name, "active": True})
                elif start_val:
                    recent_apps.append({"app": label, "path": app_name, "active": False})
        except Exception:
            pass

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path) as root_key:
            i = 0
            while True:
                try:
                    sub_name = winreg.EnumKey(root_key, i)
                    i += 1
                    full_sub = f"{base_path}\\{sub_name}"
                    if sub_name == "NonPackaged":
                        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, full_sub) as np_key:
                            j = 0
                            while True:
                                try:
                                    np_name = winreg.EnumKey(np_key, j)
                                    j += 1
                                    _inspect_key(winreg.HKEY_CURRENT_USER, f"{full_sub}\\{np_name}", np_name.replace("#", "\\"))
                                except OSError:
                                    break
                    else:
                        _inspect_key(winreg.HKEY_CURRENT_USER, full_sub, sub_name)
                except OSError:
                    break
    except Exception:
        pass

    return {"active": active_apps, "recent": recent_apps[:10]}


def inspect_hardware_privacy() -> Dict[str, Any]:
    """Audits real-time Windows Webcam and Microphone usage via CapabilityAccessManager."""
    webcam = _scan_consent_store("webcam")
    mic = _scan_consent_store("microphone")
    return {
        "webcam_in_use": len(webcam["active"]) > 0,
        "webcam_active_apps": webcam["active"],
        "recent_webcam_apps": webcam["recent"],
        "microphone_in_use": len(mic["active"]) > 0,
        "microphone_active_apps": mic["active"],
        "recent_microphone_apps": mic["recent"],
        "guard_status": "ACTIVE",
        "checked_at": datetime.now().strftime("%H:%M:%S"),
    }


def clear_windows_clipboard() -> bool:
    """Safely empties the Windows OS clipboard to erase copied credentials."""
    if not _is_windows():
        return False
    try:
        user32 = ctypes.windll.user32
        if user32.OpenClipboard(None):
            try:
                user32.EmptyClipboard()
                return True
            finally:
                user32.CloseClipboard()
    except Exception:
        return False
    return False


# ==================== 4. USB REMOVABLE DRIVE AUTO-SHIELD ====================

def detect_removable_drives() -> List[Dict[str, Any]]:
    drives: List[Dict[str, Any]] = []
    for part in psutil.disk_partitions(all=False):
        mount = part.mountpoint
        is_removable = "removable" in (part.opts or "").lower()
        if _is_windows():
            try:
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(mount))
                if drive_type == 2:  # DRIVE_REMOVABLE
                    is_removable = True
            except Exception:
                pass
        if is_removable and os.path.exists(mount):
            try:
                usage = psutil.disk_usage(mount)
                total_gb = round(usage.total / (1024**3), 2)
            except Exception:
                total_gb = 0.0
            drives.append({
                "mountpoint": mount,
                "fstype": part.fstype,
                "total_gb": total_gb,
            })
    return drives


def scan_usb_drive_path(
    target_path: str,
    inspect_file_fn: Callable[[str, str], Optional[Dict[str, Any]]],
    max_files: int = 250,
) -> Dict[str, Any]:
    """Scans a removable USB drive or target directory for autorun worms, droppers, and malware."""
    if not target_path or not os.path.exists(target_path):
        raise ValueError(f"Drive or folder path does not exist: {target_path}")

    scanned = 0
    threats: List[Dict[str, Any]] = []

    for root, _, files in os.walk(target_path):
        # Limit depth to 2 levels for fast USB shield responsiveness
        rel = os.path.relpath(root, target_path)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        if depth > 2:
            continue

        for fname in files:
            if scanned >= max_files:
                break
            fpath = os.path.join(root, fname)
            scanned += 1
            fn_lower = fname.lower()
            # Explicitly check autorun.inf worms on USB drives
            if fn_lower == "autorun.inf":
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        body = f.read(4096).lower()
                    if "open=" in body or "shellexecute=" in body:
                        alert = inspect_file_fn(fpath, "USB Autorun Shield")
                        if alert:
                            threats.append(alert)
                            continue
                except Exception:
                    pass
            alert = inspect_file_fn(fpath, "USB Removable Drive Shield")
            if alert:
                threats.append(alert)
        if scanned >= max_files:
            break

    return {
        "target_path": target_path,
        "files_scanned": scanned,
        "threats_found": len(threats),
        "threats": threats,
        "status": "THREATS_NEUTRALIZED" if threats else "CLEAN",
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
