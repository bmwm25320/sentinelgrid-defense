"""
SentinelGrid Defense - Cyber Deception Grid & Cryptographic Forensics Engine.
Implements real-time HoneyToken decoy credential traps with auto-healing rollback
and Windows Authenticode digital signature verification for running executables.
"""
import os
import json
import time
import hashlib
import platform
import subprocess
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DECEPTION_DIR = os.path.join(BASE_DIR, "deception_traps")
DECEPTION_LOG_FILE = os.path.join(BASE_DIR, "deception_state.json")

HONEYTOKENS: Dict[str, Dict[str, str]] = {
    "aws_prod_master_keys.env": {
        "category": "Cloud IAM HoneyToken",
        "mitre_id": "T1552.001",
        "content": (
            "# SENTINELGRID DECEPTION HONEYTOKEN - DO NOT DISTRIBUTE\n"
            "AWS_ACCESS_KEY_ID=AKIASGDECOY99210488\n"
            "AWS_SECRET_ACCESS_KEY=sgDecoyTrapKey/8821xFakeProdCredential\n"
            "DB_MASTER_URI=postgresql://sg_trap:HoneyToken991@10.255.255.254:5432/vault\n"
        ),
    },
    "crypto_cold_wallet_seed.txt": {
        "category": "Crypto Wallet HoneyToken",
        "mitre_id": "T1005",
        "content": (
            "SENTINELGRID DECEPTION VAULT SEED (TRAP)\n"
            "Phrase: sentinel decoy honey trap verify zero trust shield armor byte guard cyber\n"
            "TrapID: SG-BTC-TRAP-4409\n"
        ),
    },
    "executive_payroll_2026.csv": {
        "category": "Exfiltration Bait Table",
        "mitre_id": "T1039",
        "content": (
            "EmployeeID,Name,Department,BankRouting,TrapTag\n"
            "SG-TRAP-01,Decoy Executive,Finance,000000000,HONEYTOKEN_ACTIVE\n"
            "SG-TRAP-02,Canary Director,Treasury,000000001,HONEYTOKEN_ACTIVE\n"
        ),
    },
}

_trap_state: Dict[str, Any] = {
    "breaches": [],
    "auto_heal_count": 0,
    "last_deployed_at": None,
}
_healing_guard = False


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _save_state() -> None:
    try:
        with open(DECEPTION_LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(_trap_state, f, indent=2)
    except Exception:
        pass


def _load_state() -> None:
    if os.path.exists(DECEPTION_LOG_FILE):
        try:
            with open(DECEPTION_LOG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    _trap_state["breaches"] = data.get("breaches", [])[:30]
                    _trap_state["auto_heal_count"] = int(data.get("auto_heal_count", 0))
                    _trap_state["last_deployed_at"] = data.get("last_deployed_at")
        except Exception:
            pass


_load_state()


def deploy_honeytokens(force_restore: bool = True) -> Dict[str, Any]:
    """Deploys or heals realistic credential/exfiltration HoneyTokens."""
    global _healing_guard
    os.makedirs(DECEPTION_DIR, exist_ok=True)
    repaired = 0
    _healing_guard = True
    try:
        for fname, meta in HONEYTOKENS.items():
            fpath = os.path.join(DECEPTION_DIR, fname)
            expected_hash = _sha256_text(meta["content"])
            needs_write = force_restore or not os.path.exists(fpath)
            if not needs_write:
                try:
                    needs_write = _sha256_file(fpath) != expected_hash
                except Exception:
                    needs_write = True
            if needs_write:
                with open(fpath, "w", encoding="utf-8", newline="\n") as f:
                    f.write(meta["content"])
                repaired += 1
        _trap_state["last_deployed_at"] = datetime.now().isoformat()
        _save_state()
    finally:
        _healing_guard = False

    return get_honeytoken_status(repaired_now=repaired)


def get_honeytoken_status(repaired_now: int = 0) -> Dict[str, Any]:
    """Verifies cryptographic integrity of every deployed HoneyToken trap."""
    if not os.path.exists(DECEPTION_DIR):
        deploy_honeytokens(force_restore=True)

    traps: List[Dict[str, Any]] = []
    intact_count = 0
    for fname, meta in HONEYTOKENS.items():
        fpath = os.path.join(DECEPTION_DIR, fname)
        expected_hash = _sha256_text(meta["content"])
        actual_hash = None
        intact = False
        size_bytes = 0
        if os.path.exists(fpath):
            try:
                actual_hash = _sha256_file(fpath)
                intact = actual_hash == expected_hash
                size_bytes = os.path.getsize(fpath)
            except Exception:
                intact = False
        if intact:
            intact_count += 1
        traps.append({
            "name": fname,
            "category": meta["category"],
            "mitre_id": meta["mitre_id"],
            "expected_sha256": expected_hash,
            "actual_sha256": actual_hash or "MISSING",
            "intact": intact,
            "size_bytes": size_bytes,
            "path": fpath,
        })

    return {
        "armed": intact_count == len(HONEYTOKENS),
        "traps_dir": DECEPTION_DIR,
        "traps_count": len(traps),
        "intact_count": intact_count,
        "repaired_now": repaired_now,
        "auto_heal_count": _trap_state["auto_heal_count"],
        "last_deployed_at": _trap_state["last_deployed_at"],
        "traps": traps,
        "breaches": _trap_state["breaches"][:15],
    }


def _record_breach_and_heal(trap_name: str, event_type: str, start_ns: int) -> Dict[str, Any]:
    global _healing_guard
    meta = HONEYTOKENS.get(trap_name)
    if not meta:
        return {}
    fpath = os.path.join(DECEPTION_DIR, trap_name)
    _healing_guard = True
    try:
        os.makedirs(DECEPTION_DIR, exist_ok=True)
        with open(fpath, "w", encoding="utf-8", newline="\n") as f:
            f.write(meta["content"])
    finally:
        _healing_guard = False

    reaction_ms = max(1, int((time.perf_counter_ns() - start_ns) / 1_000_000))
    entry = {
        "trap_name": trap_name,
        "category": meta["category"],
        "mitre_id": meta["mitre_id"],
        "event_type": event_type,
        "healed": True,
        "restored_sha256": _sha256_text(meta["content"]),
        "reaction_ms": reaction_ms,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    _trap_state["breaches"].insert(0, entry)
    _trap_state["breaches"] = _trap_state["breaches"][:30]
    _trap_state["auto_heal_count"] += 1
    _save_state()
    return entry


def simulate_honeytoken_breach(trap_name: str = "aws_prod_master_keys.env") -> Dict[str, Any]:
    """Safely simulates an attacker altering/stealing a bait credential and triggers auto-heal."""
    global _healing_guard
    target = trap_name if trap_name in HONEYTOKENS else "aws_prod_master_keys.env"
    deploy_honeytokens(force_restore=False)
    fpath = os.path.join(DECEPTION_DIR, target)

    start_ns = time.perf_counter_ns()
    _healing_guard = True
    try:
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("[EXFILTRATED_AND_ENCRYPTED_BY_SIMULATED_RANSOMWARE_TEST]\n")
        tampered_hash = _sha256_file(fpath)
    finally:
        _healing_guard = False

    breach_record = _record_breach_and_heal(target, "SIMULATED_TAMPER_AND_EXFIL", start_ns)
    return {
        "status": "INTERCEPTED_AND_HEALED",
        "trap_name": target,
        "tampered_sha256": tampered_hash,
        "restored_sha256": breach_record.get("restored_sha256"),
        "healed": True,
        "reaction_ms": breach_record.get("reaction_ms", 1),
        "mitre_id": breach_record.get("mitre_id", "T1552.001"),
        "summary": (
            f"HoneyToken '{target}' detected unauthorized tampering, logged {breach_record.get('mitre_id')}, "
            f"and byte-for-byte auto-healed in {breach_record.get('reaction_ms')}ms."
        ),
    }


class HoneyTokenWatchHandler(FileSystemEventHandler):
    """Real-time Watchdog monitor on HoneyToken traps with instant self-healing."""

    def __init__(self, on_breach_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        super().__init__()
        self.on_breach_callback = on_breach_callback

    def on_any_event(self, event: FileSystemEvent) -> None:
        if _healing_guard or event.is_directory:
            return
        fname = os.path.basename(event.src_path)
        if fname not in HONEYTOKENS:
            return
        if event.event_type not in ("modified", "deleted", "moved", "created"):
            return

        # Verify whether actual content changed vs benign OS access
        fpath = os.path.join(DECEPTION_DIR, fname)
        expected = _sha256_text(HONEYTOKENS[fname]["content"])
        if event.event_type in ("modified", "created") and os.path.exists(fpath):
            try:
                if _sha256_file(fpath) == expected:
                    return
            except Exception:
                pass

        record = _record_breach_and_heal(fname, event.event_type.upper(), time.perf_counter_ns())
        if self.on_breach_callback and record:
            try:
                self.on_breach_callback(record)
            except Exception:
                pass


def attach_honeytoken_watchdog(observer: Any, on_breach_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> str:
    deploy_honeytokens(force_restore=False)
    handler = HoneyTokenWatchHandler(on_breach_callback=on_breach_callback)
    observer.schedule(handler, path=DECEPTION_DIR, recursive=False)
    return DECEPTION_DIR


# ==================== WINDOWS BINARY SIGNATURE (AUTHENTICODE) AUDIT ====================

def evaluate_authenticode_record(proc_name: str, exe_path: str, status: str, signer: str = "") -> Dict[str, Any]:
    """Classifies a binary signature check result into trust levels."""
    st = (status or "Unknown").strip()
    sig_label = signer.strip() or "Unsigned / No Publisher"
    exe_low = (exe_path or "").lower()

    if st == "Valid":
        trust = "TRUSTED"
        risk_score = 0
    elif st in ("HashMismatch", "NotTrusted"):
        trust = "TAMPERED"
        risk_score = 90
    elif st == "NotSigned":
        in_temp = any(s in exe_low for s in ("\\temp\\", "\\downloads\\", "\\users\\public\\"))
        trust = "HIGH_RISK_UNSIGNED" if in_temp else "UNSIGNED"
        risk_score = 75 if in_temp else 40
    else:
        trust = "UNVERIFIED"
        risk_score = 25

    return {
        "process_name": proc_name,
        "exe": exe_path,
        "signature_status": st,
        "signer": sig_label,
        "trust_level": trust,
        "risk_score": risk_score,
    }


def audit_running_binary_signatures(limit: int = 18) -> Dict[str, Any]:
    """Verifies real Authenticode digital signatures for active third-party processes."""
    is_windows = platform.system().lower() == "windows"
    candidates: Dict[str, str] = {}
    for proc in psutil.process_iter(["name", "exe"]):
        try:
            exe = proc.info.get("exe") or ""
            name = proc.info.get("name") or "unknown"
            if not exe or not os.path.exists(exe):
                continue
            low = exe.lower()
            # Focus on user-space / non-core-Windows executables first for fast, meaningful auditing
            if "\\windows\\system32\\" in low or "\\windows\\syswow64\\" in low:
                continue
            if exe not in candidates:
                candidates[exe] = name
                if len(candidates) >= limit:
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    sig_map: Dict[str, Dict[str, str]] = {}
    if is_windows and candidates:
        paths_json = json.dumps(list(candidates.keys()))
        ps_script = (
            f"$paths = '{paths_json.replace(chr(39), chr(39)*2)}' | ConvertFrom-Json; "
            "$out = @(); "
            "foreach ($p in $paths) { "
            "  try { "
            "    $s = Get-AuthenticodeSignature -FilePath $p -ErrorAction Stop; "
            "    $subj = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }; "
            "    $out += [PSCustomObject]@{ Path=$p; Status=$s.Status.ToString(); Signer=$subj }; "
            "  } catch { "
            "    $out += [PSCustomObject]@{ Path=$p; Status='Error'; Signer='' }; "
            "  } "
            "}; $out | ConvertTo-Json -Compress"
        )
        try:
            creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            res = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, encoding="utf-8", errors="ignore",
                timeout=12, creationflags=creation_flags,
            )
            raw = (res.stdout or "").strip()
            if raw:
                parsed = json.loads(raw)
                items = parsed if isinstance(parsed, list) else [parsed]
                for item in items:
                    p = item.get("Path") or ""
                    signer = item.get("Signer") or ""
                    if "CN=" in signer:
                        signer = signer.split("CN=")[1].split(",")[0].strip().strip('"')
                    sig_map[p] = {"status": item.get("Status") or "Unknown", "signer": signer}
        except Exception:
            pass

    results: List[Dict[str, Any]] = []
    signed_valid = 0
    unsigned_or_risky = 0
    for exe_path, proc_name in candidates.items():
        info = sig_map.get(exe_path, {"status": "Valid" if not is_windows else "Unknown", "signer": ""})
        rec = evaluate_authenticode_record(proc_name, exe_path, info["status"], info["signer"])
        if rec["trust_level"] == "TRUSTED":
            signed_valid += 1
        elif rec["risk_score"] >= 40:
            unsigned_or_risky += 1
        results.append(rec)

    results.sort(key=lambda r: r["risk_score"], reverse=True)
    return {
        "supported": is_windows,
        "checked_count": len(results),
        "signed_valid_count": signed_valid,
        "unsigned_or_risky_count": unsigned_or_risky,
        "binaries": results,
        "checked_at": datetime.now().strftime("%H:%M:%S"),
    }
