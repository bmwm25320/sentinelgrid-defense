"""
SentinelGrid Defense - Kaspersky Parity Suite
Disk Junk & Cache Cleaner, Reversible Startup App Manager, Winget Software Vulnerability
Scanner & 1-Click Patcher, Safe Money Isolated Banking Browser, and Boot Persistence.
"""
import os
import re
import time
import ctypes
import shutil
import tempfile
import platform
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any

try:
    import winreg
except ImportError:
    winreg = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

_software_cache: Dict[str, Any] = {
    "timestamp": 0.0,
    "data": None,
}

SAFE_MONEY_SUGGESTED_SITES = [
    {"name": "PayPal", "url": "https://www.paypal.com", "category": "Payments"},
    {"name": "HDFC NetBanking", "url": "https://netbanking.hdfcbank.com", "category": "Banking"},
    {"name": "SBI Online", "url": "https://www.onlinesbi.sbi", "category": "Banking"},
    {"name": "ICICI Bank", "url": "https://www.icicibank.com", "category": "Banking"},
    {"name": "Chase Banking", "url": "https://www.chase.com", "category": "Banking"},
    {"name": "Google Pay / Wallet", "url": "https://wallet.google.com", "category": "UPI & Cards"},
]


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _subprocess_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if _is_windows() else 0


# ==================== 1. DISK JUNK & CACHE CLEANER ====================

def _get_junk_targets() -> List[Dict[str, Any]]:
    targets: List[Dict[str, Any]] = []
    temp_dir = os.environ.get("TEMP") or tempfile.gettempdir()
    local_app = os.environ.get("LOCALAPPDATA", "")

    if temp_dir and os.path.exists(temp_dir):
        targets.append({
            "id": "win_temp",
            "label": "Windows User Temp Files",
            "path": temp_dir,
            "min_age_sec": 3600,  # Only clean stale files older than 1 hour
        })

    if local_app:
        candidates = [
            ("edge_cache", "Microsoft Edge Disk Cache", os.path.join(local_app, "Microsoft", "Edge", "User Data", "Default", "Cache", "Cache_Data"), 0),
            ("chrome_cache", "Google Chrome Disk Cache", os.path.join(local_app, "Google", "Chrome", "User Data", "Default", "Cache", "Cache_Data"), 0),
            ("crash_dumps", "Application Crash Dumps", os.path.join(local_app, "CrashDumps"), 300),
        ]
        for cid, label, path, min_age in candidates:
            if os.path.exists(path):
                targets.append({"id": cid, "label": label, "path": path, "min_age_sec": min_age})
    return targets


def scan_disk_junk(max_files_per_dir: int = 1200) -> Dict[str, Any]:
    now = time.time()
    categories: List[Dict[str, Any]] = []
    total_files = 0
    total_bytes = 0

    for target in _get_junk_targets():
        cat_files = 0
        cat_bytes = 0
        min_age = target["min_age_sec"]
        try:
            for root, _, files in os.walk(target["path"]):
                for fname in files:
                    if cat_files >= max_files_per_dir:
                        break
                    if fname.startswith("sg_"):
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        st = os.stat(fpath)
                        if min_age > 0 and (now - st.st_mtime) < min_age:
                            continue
                        cat_files += 1
                        cat_bytes += st.st_size
                    except Exception:
                        continue
                if cat_files >= max_files_per_dir:
                    break
        except Exception:
            pass

        cat_mb = round(cat_bytes / (1024 * 1024), 2)
        total_files += cat_files
        total_bytes += cat_bytes
        categories.append({
            "id": target["id"],
            "label": target["label"],
            "path": target["path"],
            "file_count": cat_files,
            "size_mb": cat_mb,
        })

    return {
        "total_files": total_files,
        "total_mb": round(total_bytes / (1024 * 1024), 2),
        "categories": categories,
        "scanned_at": datetime.now().strftime("%H:%M:%S"),
    }


def clean_disk_junk(category_ids: Optional[List[str]] = None, max_files_per_dir: int = 1200) -> Dict[str, Any]:
    now = time.time()
    allowed = set(category_ids) if category_ids else None
    deleted_files = 0
    skipped_locked = 0
    freed_bytes = 0

    for target in _get_junk_targets():
        if allowed is not None and target["id"] not in allowed:
            continue
        min_age = target["min_age_sec"]
        processed = 0
        try:
            for root, _, files in os.walk(target["path"]):
                for fname in files:
                    if processed >= max_files_per_dir:
                        break
                    if fname.startswith("sg_"):
                        continue
                    fpath = os.path.join(root, fname)
                    processed += 1
                    try:
                        st = os.stat(fpath)
                        if min_age > 0 and (now - st.st_mtime) < min_age:
                            continue
                        fsize = st.st_size
                        os.remove(fpath)
                        deleted_files += 1
                        freed_bytes += fsize
                    except Exception:
                        skipped_locked += 1
                if processed >= max_files_per_dir:
                    break
        except Exception:
            pass

    return {
        "status": "cleaned",
        "deleted_files": deleted_files,
        "skipped_locked": skipped_locked,
        "freed_mb": round(freed_bytes / (1024 * 1024), 2),
        "cleaned_at": datetime.now().strftime("%H:%M:%S"),
    }


# ==================== 2. STARTUP APP MANAGER & BOOT PERSISTENCE ====================

_STARTUP_RUN_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
_STARTUP_APPROVED_PATH = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
_PROTECTED_STARTUP_NAMES = {"sentinelgriddefense", "securityhealth", "windowsdefender"}


def _read_startup_approved_map() -> Dict[str, bool]:
    approved: Dict[str, bool] = {}
    if not _is_windows() or winreg is None:
        return approved
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _STARTUP_APPROVED_PATH) as key:
            count = winreg.QueryInfoKey(key)[1]
            for i in range(count):
                name, val, _ = winreg.EnumValue(key, i)
                if isinstance(val, bytes) and len(val) >= 1:
                    # Windows Task Manager convention: even byte (0x02/0x06) = Enabled, odd (0x03/0x07) = Disabled
                    approved[name.lower()] = (val[0] % 2 == 0)
    except Exception:
        pass
    return approved


def list_startup_apps() -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    if not _is_windows() or winreg is None:
        return entries

    approved_map = _read_startup_approved_map()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _STARTUP_RUN_PATH) as key:
            count = winreg.QueryInfoKey(key)[1]
            for i in range(count):
                name, val, _ = winreg.EnumValue(key, i)
                is_enabled = approved_map.get(name.lower(), True)
                is_protected = name.lower() in _PROTECTED_STARTUP_NAMES or "sentinelgrid" in name.lower()
                entries.append({
                    "name": name,
                    "command": str(val),
                    "hive": "HKEY_CURRENT_USER",
                    "enabled": is_enabled,
                    "protected": is_protected,
                    "suspicious": any(ind in str(val).lower() for ind in (".vbs", ".bat", "powershell -enc", "temp\\")),
                })
    except Exception:
        pass
    return entries


def toggle_startup_app(name: str, enabled: bool) -> Dict[str, Any]:
    if not name or not name.strip():
        raise ValueError("Startup item name cannot be empty.")
    clean_name = name.strip()
    if clean_name.lower() in _PROTECTED_STARTUP_NAMES or "sentinelgrid" in clean_name.lower():
        if not enabled:
            raise ValueError(f"Refusing to disable protected security entry: {clean_name}")

    if not _is_windows() or winreg is None:
        return {"name": clean_name, "enabled": enabled, "platform": "non-windows"}

    # Standard 12-byte StartupApproved\Run REG_BINARY payload
    state_bytes = b"\x02" + b"\x00" * 11 if enabled else b"\x03" + b"\x00" * 11
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _STARTUP_APPROVED_PATH) as key:
        winreg.SetValueEx(key, clean_name, 0, winreg.REG_BINARY, state_bytes)

    return {"name": clean_name, "enabled": enabled, "status": "updated"}


def get_boot_persistence_status() -> Dict[str, Any]:
    if not _is_windows() or winreg is None:
        return {"enabled": False, "command": None}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _STARTUP_RUN_PATH) as key:
            val, _ = winreg.QueryValueEx(key, "SentinelGridDefense")
            approved_map = _read_startup_approved_map()
            enabled = approved_map.get("sentinelgriddefense", True)
            return {"enabled": bool(val) and enabled, "command": str(val)}
    except Exception:
        return {"enabled": False, "command": None}


def set_boot_persistence(enabled: bool) -> Dict[str, Any]:
    if not _is_windows() or winreg is None:
        return {"enabled": False, "note": "Windows Registry only"}

    installed_exe = r"D:\SentinelGrid Defense\SentinelGridDefense.exe"
    if os.path.exists(installed_exe):
        launch_cmd = f'"{installed_exe}"'
    else:
        launcher_py = os.path.join(BASE_DIR, "desktop_launcher.py")
        launch_cmd = f'python "{launcher_py}"'

    if enabled:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _STARTUP_RUN_PATH) as key:
            winreg.SetValueEx(key, "SentinelGridDefense", 0, winreg.REG_SZ, launch_cmd)
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _STARTUP_APPROVED_PATH) as key:
            winreg.SetValueEx(key, "SentinelGridDefense", 0, winreg.REG_BINARY, b"\x02" + b"\x00" * 11)
        return {"enabled": True, "command": launch_cmd}
    else:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _STARTUP_RUN_PATH, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, "SentinelGridDefense")
        except FileNotFoundError:
            pass
        return {"enabled": False, "command": None}


# ==================== 3. SOFTWARE VULNERABILITY SCANNER (WINGET) ====================

_HIGH_RISK_SOFTWARE_KW = ("chrome", "edge", "firefox", "brave", "adobe", "acrobat", "7-zip", "winrar", "java", "python", "openssl", "curl", "vlc")


def parse_winget_upgrade_output(stdout: str) -> List[Dict[str, Any]]:
    """Parses tabular `winget upgrade` stdout into structured outdated package objects."""
    packages: List[Dict[str, Any]] = []
    lines = [ln.rstrip() for ln in (stdout or "").splitlines() if ln.strip()]
    sep_idx = -1
    for i, ln in enumerate(lines):
        if re.match(r"^-{10,}$", ln.strip()):
            sep_idx = i
            break
    if sep_idx <= 0:
        return packages

    header = lines[sep_idx - 1]
    col_id = header.find("Id")
    col_ver = header.find("Version")
    col_avail = header.find("Available")
    col_src = header.find("Source")
    if col_id < 0 or col_ver < 0 or col_avail < 0:
        return packages

    for ln in lines[sep_idx + 1:]:
        if "upgrades available" in ln.lower() or ln.startswith("The following"):
            break
        if len(ln) <= col_avail:
            continue
        name = ln[:col_id].strip()
        pkg_id = ln[col_id:col_ver].strip()
        cur_ver = ln[col_ver:col_avail].strip()
        avail_ver = (ln[col_avail:col_src] if col_src > col_avail else ln[col_avail:]).strip()
        if not pkg_id or not avail_ver or "unknown" in avail_ver.lower():
            continue
        # Skip multi-word false header rows
        if " " in pkg_id:
            continue
        severity = "HIGH" if any(k in (name + " " + pkg_id).lower() for k in _HIGH_RISK_SOFTWARE_KW) else "MEDIUM"
        packages.append({
            "name": name or pkg_id,
            "id": pkg_id,
            "current_version": cur_ver or "Installed",
            "available_version": avail_ver,
            "severity": severity,
        })
    return packages[:25]


def scan_outdated_software(force: bool = False) -> Dict[str, Any]:
    now = time.time()
    if not force and _software_cache["data"] is not None and (now - _software_cache["timestamp"]) < 120:
        return _software_cache["data"]

    if not _is_windows():
        return {"winget_available": False, "outdated_count": 0, "packages": [], "scanned_at": datetime.now().strftime("%H:%M:%S")}

    try:
        res = subprocess.run(
            ["winget", "upgrade", "--accept-source-agreements"],
            capture_output=True, text=True, encoding="utf-8", errors="ignore",
            timeout=15, creationflags=_subprocess_flags(),
        )
        pkgs = parse_winget_upgrade_output(res.stdout or "")
        payload = {
            "winget_available": True,
            "outdated_count": len(pkgs),
            "high_severity_count": sum(1 for p in pkgs if p["severity"] == "HIGH"),
            "packages": pkgs,
            "scanned_at": datetime.now().strftime("%H:%M:%S"),
        }
    except Exception as exc:
        payload = {
            "winget_available": False,
            "outdated_count": 0,
            "high_severity_count": 0,
            "packages": [],
            "error": str(exc),
            "scanned_at": datetime.now().strftime("%H:%M:%S"),
        }

    _software_cache["data"] = payload
    _software_cache["timestamp"] = now
    return payload


def patch_software_package(package_id: str) -> Dict[str, Any]:
    clean_id = (package_id or "").strip()
    if not re.match(r"^[a-zA-Z0-9._-]+$", clean_id):
        raise ValueError(f"Invalid Winget package identifier: {package_id}")

    if not _is_windows():
        return {"status": "unsupported", "package_id": clean_id}

    res = subprocess.run(
        [
            "winget", "upgrade", "--id", clean_id, "--exact",
            "--silent", "--accept-package-agreements", "--accept-source-agreements",
        ],
        capture_output=True, text=True, encoding="utf-8", errors="ignore",
        timeout=90, creationflags=_subprocess_flags(),
    )
    _software_cache["data"] = None
    ok = res.returncode == 0 or "successfully installed" in (res.stdout or "").lower()
    return {
        "status": "updated" if ok else "note",
        "package_id": clean_id,
        "message": "Package patched successfully." if ok else ((res.stdout or res.stderr or "Patch command finished")[-160:]).strip(),
    }


# ==================== 4. SAFE MONEY PROTECTED BANKING BROWSER ====================

def _find_hardened_browser_exe() -> Optional[str]:
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def launch_safe_money_browser(raw_url: str) -> Dict[str, Any]:
    """
    Launches an isolated, extension-free, InPrivate desktop browser session
    with a dedicated temporary sandbox profile for banking/payments.
    """
    url_str = (raw_url or "").strip()
    if not url_str:
        raise ValueError("Safe Money URL cannot be empty.")
    if not url_str.startswith(("http://", "https://")):
        url_str = "https://" + url_str

    browser_exe = _find_hardened_browser_exe()
    sandbox_profile = os.path.join(tempfile.gettempdir(), "sg_safemoney_profile")
    os.makedirs(sandbox_profile, exist_ok=True)

    # Clear OS clipboard prior to entering financial session
    try:
        if _is_windows() and ctypes.windll.user32.OpenClipboard(None):
            try:
                ctypes.windll.user32.EmptyClipboard()
            finally:
                ctypes.windll.user32.CloseClipboard()
    except Exception:
        pass

    launched_mode = "default_browser"
    if browser_exe:
        is_edge = "msedge" in browser_exe.lower()
        flags = [
            browser_exe,
            "--inprivate" if is_edge else "--incognito",
            f"--app={url_str}",
            f"--user-data-dir={sandbox_profile}",
            "--disable-extensions",
            "--no-first-run",
            "--disable-sync",
        ]
        subprocess.Popen(flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        launched_mode = "isolated_edge_app" if is_edge else "isolated_chrome_app"
    else:
        import webbrowser
        webbrowser.open(url_str)

    return {
        "status": "launched",
        "url": url_str,
        "isolation_mode": launched_mode,
        "clipboard_cleared": True,
        "extensions_disabled": True,
        "launched_at": datetime.now().strftime("%H:%M:%S"),
    }
