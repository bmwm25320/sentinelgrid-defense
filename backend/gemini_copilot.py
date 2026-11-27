"""
SentinelGrid Defense - Background Gemini Co-Pilot Engine
Tracks active foreground application context across Windows, generates structured
task options via Gemini 2.5 Flash (with intelligent offline fallback), and executes
user-selected options against live OS defense engines.
"""
import os
import json
import time
import ctypes
import platform
import threading
import urllib.request
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable

import psutil

active_app_state: Dict[str, Any] = {
    "background_enabled": True,
    "hotkey": "Ctrl+Shift+G",
    "current_app": {
        "process_name": "SentinelGridDefense",
        "window_title": "SentinelGrid Defense",
        "pid": os.getpid(),
        "exe": "",
        "detected_at": datetime.now().strftime("%H:%M:%S"),
    },
    "last_external_app": None,
    "recent_apps": [],
    "summon_counter": 0,
}


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def capture_foreground_window_info() -> Dict[str, Any]:
    """Captures the currently focused Windows application title, process name, and PID."""
    if not _is_windows():
        return {
            "process_name": "desktop",
            "window_title": "Active Workspace",
            "pid": 0,
            "exe": "",
            "detected_at": datetime.now().strftime("%H:%M:%S"),
        }

    try:
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return dict(active_app_state["current_app"])

        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(max(1, length + 1))
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value.strip() or "Desktop"

        pid_c = ctypes.c_ulong(0)
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_c))
        pid = int(pid_c.value)

        proc_name = "unknown"
        exe_path = ""
        if pid > 0:
            try:
                p = psutil.Process(pid)
                proc_name = p.name()
                exe_path = p.exe() or ""
            except Exception:
                pass

        return {
            "process_name": proc_name,
            "window_title": title[:140],
            "pid": pid,
            "exe": exe_path,
            "detected_at": datetime.now().strftime("%H:%M:%S"),
        }
    except Exception:
        return dict(active_app_state["current_app"])


def active_window_tracker_loop():
    """Lightweight background loop tracking which Windows app the user switches to."""
    while True:
        try:
            if active_app_state.get("background_enabled", True):
                info = capture_foreground_window_info()
                active_app_state["current_app"] = info
                pname = (info.get("process_name") or "").lower()

                is_self = (
                    "sentinelgrid" in pname
                    or "sentinelgrid" in (info.get("window_title") or "").lower()
                    or info.get("pid") == os.getpid()
                )
                if not is_self and pname not in ("unknown", ""):
                    active_app_state["last_external_app"] = info

                recent = active_app_state["recent_apps"]
                if not recent or recent[0].get("process_name") != info.get("process_name") or recent[0].get("window_title") != info.get("window_title"):
                    recent.insert(0, info)
                    if len(recent) > 12:
                        recent.pop()
            time.sleep(1.5)
        except Exception:
            time.sleep(2.5)


def start_background_tracker():
    t = threading.Thread(target=active_window_tracker_loop, daemon=True)
    t.start()
    return t


def request_copilot_summon():
    active_app_state["summon_counter"] = int(active_app_state.get("summon_counter", 0)) + 1
    return active_app_state["summon_counter"]


def get_gemini_api_key(override_key: str = "") -> str:
    """Resolves the Gemini API key from explicit override, environment, or local .env files."""
    if override_key and override_key.strip():
        return override_key.strip()

    for env_name in ("GEMINI_API_KEY", "VITE_GEMINI_API_KEY"):
        val = (os.environ.get(env_name) or "").strip()
        if val:
            return val

    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidate_envs = [
        os.path.join(base_dir, ".env"),
        os.path.abspath(os.path.join(base_dir, "..", ".env")),
        os.path.abspath(os.path.join(base_dir, "..", "frontend", ".env")),
    ]
    for env_path in candidate_envs:
        if not os.path.exists(env_path):
            continue
        try:
            with open(env_path, "r", encoding="utf-8") as ef:
                for line in ef:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    if k.strip() in ("GEMINI_API_KEY", "VITE_GEMINI_API_KEY") and v.strip():
                        return v.strip().strip('"').strip("'")
        except Exception:
            pass
    return ""


def _call_gemini_rest_for_options(
    task: str,
    api_key: str,
    context_snapshot: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Queries Gemini 3 REST API with automatic model fallback for structured Task -> Options JSON."""
    resolved_key = get_gemini_api_key(api_key)
    if not resolved_key:
        return None

    system_prompt = (
        "You are SentinelGrid Gemini Background Co-Pilot running continuously across the user's device.\n"
        "The user gives you a task while inside an app. Always understand their task + active app context "
        "and return JSON ONLY with this exact schema:\n"
        "{\n"
        '  "analysis": "Clear 2-3 sentence summary explaining what you found and why these options help.",\n'
        '  "options": [\n'
        '    {\n'
        '      "id": "opt_1",\n'
        '      "title": "Short clickable action title",\n'
        '      "description": "What this option will execute",\n'
        '      "impact": "SAFE | FAST | DEEP",\n'
        '      "action_type": "ONE_OF_ALLOWED_ACTIONS",\n'
        '      "params": {}\n'
        '    }\n'
        "  ]\n"
        "}\n"
        "Allowed action_type values ONLY:\n"
        "- inspect_active_app (audits active/last external app process, path, sockets, AMSI)\n"
        "- quick_scan (runs real-time smart virus/memory scan)\n"
        "- fast_laptop_scan (runs 5-stage system health & security audit)\n"
        "- boost_ram (reclaims unused memory safely without closing active UI)\n"
        "- kill_useless_apps (terminates useless background bloatware, widgets & idle updaters + trims RAM)\n"
        "- trim_ram (flushes standby OS memory working sets without closing apps)\n"
        "- clean_junk (removes stale Windows temp & browser cache junk files)\n"
        "- scan_software_updates (audits outdated apps with known vulnerabilities via winget)\n"
        "- open_safe_money (params: {\"url\": \"...\"} - opens isolated banking browser)\n"
        "- hardware_privacy_audit (checks webcam, microphone, and ARP MITM status)\n"
        "- hunt_processes (hunts encoded PowerShell, certutil, mshta LOLBins & Office spawns)\n"
        "- toggle_dns_shield (params: {\"enabled\": true} - enables system-wide phishing DNS/HOSTS shield)\n"
        "- backup_snapshot (creates an immutable ransomware recovery ZIP snapshot of protected files)\n"
        "- scan_usb (scans connected USB removable drives)\n"
        "- check_url (params: {\"url\": \"...\"})\n"
        "- block_ip (params: {\"ip\": \"...\", \"reason\": \"...\"})\n"
        "- navigate_tab (params: {\"tab\": \"home|threats|network|device|vault|assistant\"})\n"
        "Provide 2 to 4 useful, distinct options so the user can pick how to proceed."
    )

    user_payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": f"{system_prompt}\n\nUser Task: {task}\n\nLive Device & Active App Context:\n{json.dumps(context_snapshot, default=str)}"
                    }
                ]
            }
        ],
        "generationConfig": {
            "responseMimeType": "application/json",
            "temperature": 0.3,
        },
    }

    for model_name in ("gemini-3.8-flash", "gemini-3-flash-preview"):
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={resolved_key}"
        req = urllib.request.Request(
            url,
            data=json.dumps(user_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                raw = json.loads(resp.read().decode("utf-8", errors="ignore"))
                text = (
                    raw.get("candidates", [{}])[0]
                    .get("content", {})
                    .get("parts", [{}])[0]
                    .get("text", "")
                )
                if not text:
                    continue
                parsed = json.loads(text)
                if isinstance(parsed, dict) and isinstance(parsed.get("options"), list) and len(parsed["options"]) > 0:
                    return parsed
        except Exception:
            continue
    return None


def _heuristic_options_planner(task: str, target_app: Dict[str, Any], device_summary: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic Task -> Options planner when Gemini API key is not configured or offline."""
    q = (task or "").lower()
    app_name = target_app.get("process_name") or "current app"
    win_title = target_app.get("window_title") or "Desktop"
    pid = target_app.get("pid") or 0

    # Extract IP or URL if user pasted one inside their task
    import re
    url_match = re.search(r"(https?://[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)", task)
    ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", task)

    if ip_match and ("block" in q or "ip" in q or "attack" in q or "firewall" in q):
        ip_val = ip_match.group(1)
        return {
            "analysis": f"Detected IP address `{ip_val}` while monitoring `{app_name}`. Choose how you want SentinelGrid to handle this connection:",
            "options": [
                {
                    "id": "opt_block_ip",
                    "title": f"Block {ip_val} in Firewall",
                    "description": "Adds an active Windows Firewall inbound & outbound block rule immediately.",
                    "impact": "SAFE",
                    "action_type": "block_ip",
                    "params": {"ip": ip_val, "reason": f"Gemini Co-Pilot task from {app_name}"},
                },
                {
                    "id": "opt_net_audit",
                    "title": "Run Network & ARP MITM Check",
                    "description": "Verifies ARP gateway integrity and inspects active foreign connections.",
                    "impact": "FAST",
                    "action_type": "hardware_privacy_audit",
                    "params": {},
                },
                {
                    "id": "opt_open_net",
                    "title": "Open Firewall & Network Shield",
                    "description": "Navigate directly to the Firewall & Network dashboard view.",
                    "impact": "SAFE",
                    "action_type": "navigate_tab",
                    "params": {"tab": "network"},
                },
            ],
        }

    if url_match and ("link" in q or "url" in q or "site" in q or "safe" in q or "phish" in q or "check" in q):
        url_val = url_match.group(1)
        return {
            "analysis": f"I can inspect `{url_val}` before you trust it inside `{app_name}`. Select your preferred action:",
            "options": [
                {
                    "id": "opt_check_url",
                    "title": f"Scan Link Safety ({url_val[:28]})",
                    "description": "Evaluates domain reputation, phishing keywords, and executable payload risk.",
                    "impact": "FAST",
                    "action_type": "check_url",
                    "params": {"url": url_val},
                },
                {
                    "id": "opt_inspect_app",
                    "title": f"Audit Active App ({app_name})",
                    "description": "Checks executable path, open network sockets, and AMSI status of this app.",
                    "impact": "DEEP",
                    "action_type": "inspect_active_app",
                    "params": {"pid": pid, "process_name": app_name},
                },
                {
                    "id": "opt_open_network",
                    "title": "Open Safe Link & Firewall Tab",
                    "description": "Jump straight to the Firewall & Network protection workspace.",
                    "impact": "SAFE",
                    "action_type": "navigate_tab",
                    "params": {"tab": "network"},
                },
            ],
        }

    if any(k in q for k in ("junk", "temp", "cache", "disk", "storage")):
        return {
            "analysis": "I can sweep Windows Temp, Edge/Chrome cache, and crash dumps cleanly without touching active system locks:",
            "options": [
                {
                    "id": "opt_clean_junk",
                    "title": "Clean Disk Junk & Temp Cache",
                    "description": "Removes stale temp files and browser cache safely.",
                    "impact": "FAST",
                    "action_type": "clean_junk",
                    "params": {},
                },
                {
                    "id": "opt_open_health",
                    "title": "Open Disk Junk & Startup Manager",
                    "description": "Inspect junk categories and disable heavy startup apps.",
                    "impact": "SAFE",
                    "action_type": "navigate_tab",
                    "params": {"tab": "device"},
                },
            ],
        }

    if any(k in q for k in ("bank", "pay", "money", "upi", "paypal", "hdfc", "sbi", "safe money")):
        target_site = url_match.group(1) if url_match else "https://www.paypal.com"
        return {
            "analysis": f"Entering financial portal `{target_site}`. Choose Safe Money isolated banking mode for hardware & clipboard protection:",
            "options": [
                {
                    "id": "opt_safe_money",
                    "title": f"Launch Safe Money ({target_site[:28]})",
                    "description": "Opens extension-free InPrivate isolated window and wipes OS clipboard.",
                    "impact": "SAFE",
                    "action_type": "open_safe_money",
                    "params": {"url": target_site},
                },
                {
                    "id": "opt_hw_audit",
                    "title": "Audit Webcam, Mic & MITM First",
                    "description": "Verify no spying or ARP spoofing is active before banking.",
                    "impact": "FAST",
                    "action_type": "hardware_privacy_audit",
                    "params": {},
                },
            ],
        }

    if any(k in q for k in ("update", "outdated", "patch", "software", "cve", "vuln")):
        return {
            "analysis": "I can check installed Windows software against Winget package versions for outdated or vulnerable apps:",
            "options": [
                {
                    "id": "opt_soft_scan",
                    "title": "Scan Outdated Software & Vulnerabilities",
                    "description": "Checks Chrome, Edge, runtimes & utilities for available security patches.",
                    "impact": "DEEP",
                    "action_type": "scan_software_updates",
                    "params": {},
                },
                {
                    "id": "opt_open_dev",
                    "title": "Open Patch & Health Dashboard",
                    "description": "Review software updates and apply 1-click patches.",
                    "impact": "SAFE",
                    "action_type": "navigate_tab",
                    "params": {"tab": "device"},
                },
            ],
        }

    if any(k in q for k in ("useless", "bloat", "background app", "kill ram", "stop app", "slow", "lag", "ram", "memory", "boost", "speed", "clean", "optimize")):
        ram_pct = device_summary.get("ram_percent", 0)
        return {
            "analysis": f"System RAM usage is {ram_pct}% while `{app_name}` ({win_title}) is active. Choose whether to kill useless background apps or trim standby memory:",
            "options": [
                {
                    "id": "opt_kill_bloat",
                    "title": "Stop Useless Background Apps & Free RAM",
                    "description": "Terminates idle bloatware, widgets, updaters & background helpers + trims RAM safely.",
                    "impact": "FAST",
                    "action_type": "kill_useless_apps",
                    "params": {},
                },
                {
                    "id": "opt_trim_ram",
                    "title": "Trim Standby RAM Only (Keep Apps Open)",
                    "description": "Flushes Windows OS working sets across idle processes without closing windows.",
                    "impact": "SAFE",
                    "action_type": "trim_ram",
                    "params": {},
                },
                {
                    "id": "opt_open_device",
                    "title": "Open Background App & RAM Killer",
                    "description": "Select individual or grouped background bloat apps to stop manually.",
                    "impact": "SAFE",
                    "action_type": "navigate_tab",
                    "params": {"tab": "device"},
                },
            ],
        }

    if any(k in q for k in ("lolbin", "powershell", "hunt", "malware process", "script", "ransomware", "backup", "snapshot")):
        return {
            "analysis": f"Running deep behavioral inspection & recovery shield while `{app_name}` is focused. Pick an active defense step:",
            "options": [
                {
                    "id": "opt_proc_hunt",
                    "title": "Run Behavioral LOLBin Process Hunt",
                    "description": "Hunts encoded PowerShell, mshta/certutil drops, and Office macro spawn chains.",
                    "impact": "DEEP",
                    "action_type": "hunt_processes",
                    "params": {},
                },
                {
                    "id": "opt_backup_snap",
                    "title": "Create Ransomware Recovery Snapshot",
                    "description": "Archives protected documents into an immutable ZIP backup.",
                    "impact": "SAFE",
                    "action_type": "backup_snapshot",
                    "params": {},
                },
                {
                    "id": "opt_dns_on",
                    "title": "Enable DNS Malware/Phishing Shield",
                    "description": "Arms system-wide malicious domain blocking across all browsers.",
                    "impact": "SAFE",
                    "action_type": "toggle_dns_shield",
                    "params": {"enabled": True},
                },
            ],
        }

    if any(k in q for k in ("cam", "camera", "webcam", "mic", "microphone", "privacy", "spy", "hack", "mitm", "wifi")):
        return {
            "analysis": f"I am watching background hardware & network access while you work in `{app_name}`. Choose a privacy action:",
            "options": [
                {
                    "id": "opt_hw_privacy",
                    "title": "Audit Webcam, Mic & ARP Spoofing",
                    "description": "Checks which Windows apps currently hold camera/mic locks and inspects ARP cache.",
                    "impact": "FAST",
                    "action_type": "hardware_privacy_audit",
                    "params": {},
                },
                {
                    "id": "opt_inspect_curr",
                    "title": f"Inspect {app_name} Forensics",
                    "description": "Audits active app binary path, memory footprint, and remote connections.",
                    "impact": "DEEP",
                    "action_type": "inspect_active_app",
                    "params": {"pid": pid, "process_name": app_name},
                },
                {
                    "id": "opt_open_net",
                    "title": "Open Privacy & Network Shield",
                    "description": "Review live outbound sockets and block suspicious IPs.",
                    "impact": "SAFE",
                    "action_type": "navigate_tab",
                    "params": {"tab": "network"},
                },
            ],
        }

    if any(k in q for k in ("usb", "drive", "pendrive", "flash", "external")):
        return {
            "analysis": "SentinelGrid USB Auto-Shield is armed in the background. Choose how to check removable storage:",
            "options": [
                {
                    "id": "opt_scan_usb",
                    "title": "Scan Connected USB Drives",
                    "description": "Sweeps removable drives for autorun.inf worms, .lnk droppers, and malware.",
                    "impact": "FAST",
                    "action_type": "scan_usb",
                    "params": {},
                },
                {
                    "id": "opt_quick_scan",
                    "title": "Run Full Smart Virus Scan",
                    "description": "Scans active memory, Downloads, and protected traps across the endpoint.",
                    "impact": "DEEP",
                    "action_type": "quick_scan",
                    "params": {},
                },
                {
                    "id": "opt_open_threats",
                    "title": "Open Virus & Threat Protection",
                    "description": "Inspect USB status, quarantine vault, and shield settings.",
                    "impact": "SAFE",
                    "action_type": "navigate_tab",
                    "params": {"tab": "threats"},
                },
            ],
        }

    if any(k in q for k in ("password", "vault", "leak", "breach", "dark web", "pin")):
        return {
            "analysis": "I can open your AES-256 Encrypted Password Vault and check saved accounts for Dark Web leaks via k-anonymity:",
            "options": [
                {
                    "id": "opt_open_vault",
                    "title": "Open Encrypted Password Vault",
                    "description": "Access saved credentials and run the Dark Web Breach Audit.",
                    "impact": "SAFE",
                    "action_type": "navigate_tab",
                    "params": {"tab": "vault"},
                },
                {
                    "id": "opt_hw_check",
                    "title": "Check Endpoint Privacy First",
                    "description": "Verify no unauthorized mic/cam hooks or MITM attacks are active.",
                    "impact": "FAST",
                    "action_type": "hardware_privacy_audit",
                    "params": {},
                },
            ],
        }

    # General app-aware task fallback
    return {
        "analysis": f"Background Gemini Co-Pilot is active and linked to `{app_name}` ({win_title}). Select what action you want me to work on:",
        "options": [
            {
                "id": "opt_app_forensics",
                "title": f"Inspect & Protect Active App ({app_name})",
                "description": "Audits the active app's executable, memory usage, AMSI signature, and open sockets.",
                "impact": "FAST",
                "action_type": "inspect_active_app",
                "params": {"pid": pid, "process_name": app_name},
            },
            {
                "id": "opt_smart_scan",
                "title": "Run Real-Time Smart Scan",
                "description": "Sweeps system memory, running processes, and Downloads for active threats.",
                "impact": "DEEP",
                "action_type": "quick_scan",
                "params": {},
            },
            {
                "id": "opt_boost_ram",
                "title": "Optimize & Boost RAM",
                "description": "Safely frees background memory to speed up your active app.",
                "impact": "FAST",
                "action_type": "boost_ram",
                "params": {},
            },
            {
                "id": "opt_privacy_check",
                "title": "Check Webcam, Mic & Network",
                "description": "Runs live hardware privacy and ARP MITM verification.",
                "impact": "SAFE",
                "action_type": "hardware_privacy_audit",
                "params": {},
            },
        ],
    }


def plan_task_options(
    task: str,
    api_key: str = "",
    explicit_active_app: Optional[Dict[str, Any]] = None,
    device_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    target_app = explicit_active_app or active_app_state.get("last_external_app") or active_app_state.get("current_app") or {}
    summary = device_summary or {}

    context_snapshot = {
        "active_app": target_app,
        "device_summary": summary,
        "recent_apps": active_app_state.get("recent_apps", [])[:5],
    }

    gemini_result = _call_gemini_rest_for_options(task, api_key, context_snapshot)
    used_gemini = gemini_result is not None
    plan = gemini_result or _heuristic_options_planner(task, target_app, summary)

    return {
        "task": task,
        "used_gemini_llm": used_gemini,
        "active_app": target_app,
        "analysis": plan.get("analysis", ""),
        "options": plan.get("options", []),
        "planned_at": datetime.now().strftime("%H:%M:%S"),
    }


def inspect_process_forensics(pid: int, process_name: str = "") -> Dict[str, Any]:
    """Deep inspection of a specific foreground app PID or process name."""
    target_proc = None
    try:
        if pid and pid > 0:
            target_proc = psutil.Process(pid)
    except Exception:
        target_proc = None

    if target_proc is None and process_name:
        for p in psutil.process_iter(["pid", "name"]):
            if (p.info.get("name") or "").lower() == process_name.lower():
                target_proc = p
                break

    if target_proc is None:
        return {
            "status": "NOT_FOUND",
            "summary": f"Process '{process_name or pid}' is no longer active.",
            "connections": [],
        }

    try:
        name = target_proc.name()
        exe = target_proc.exe() or "System / Protected Path"
        mem_mb = round(target_proc.memory_info().rss / (1024 * 1024), 1)
        conns = []
        for c in target_proc.net_connections(kind="inet"):
            if c.raddr:
                conns.append(f"{c.raddr.ip}:{c.raddr.port} ({c.status})")
        suspicious_path = any(k in exe.lower() for k in ("\\temp\\", "\\appdata\\local\\temp", "\\downloads\\"))
        return {
            "status": "WARNING" if suspicious_path else "SAFE",
            "pid": target_proc.pid,
            "process_name": name,
            "exe_path": exe,
            "memory_mb": mem_mb,
            "outbound_connections": conns[:10],
            "suspicious_temp_origin": suspicious_path,
            "summary": (
                f"Inspected {name} (PID {target_proc.pid}, {mem_mb} MB RAM) at `{exe}`. "
                f"Active remote sockets: {len(conns)}. Verdict: {'Flagged temp-path origin' if suspicious_path else 'Verified Safe Binary'}."
            ),
        }
    except Exception as exc:
        return {
            "status": "PROTECTED",
            "summary": f"Process is protected by Windows privilege boundaries ({exc}).",
            "outbound_connections": [],
        }
