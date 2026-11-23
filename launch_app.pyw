"""
SentinelGrid Defense - Windows Desktop App Launcher
Launches SentinelGrid Defense in dedicated standalone desktop application mode.
"""
import os
import sys
import time
import subprocess
import urllib.request
import webbrowser

WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(WORKSPACE_DIR, "backend")
APP_URL = "http://localhost:8000"
TELEMETRY_URL = "http://127.0.0.1:8000/api/telemetry"

CREATE_NO_WINDOW = 0x08000000

def is_backend_running(timeout=0.6):
    try:
        req = urllib.request.Request(TELEMETRY_URL)
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status == 200
    except Exception:
        return False

def get_python_exe():
    py_dir = os.path.dirname(sys.executable)
    py = os.path.join(py_dir, "python.exe")
    if os.path.exists(py):
        return py
    return sys.executable

def start_backend():
    if is_backend_running():
        return None  # Already running externally

    py = get_python_exe()
    cmd = [
        py,
        "-m", "uvicorn",
        "engine:app",
        "--app-dir", BACKEND_DIR,
        "--host", "127.0.0.1",
        "--port", "8000"
    ]

    flags = CREATE_NO_WINDOW if os.name == "nt" else 0
    backend_proc = subprocess.Popen(
        cmd,
        cwd=WORKSPACE_DIR,
        creationflags=flags,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Poll until ready
    for _ in range(40):
        time.sleep(0.2)
        if is_backend_running(0.5):
            return backend_proc

    return backend_proc

def find_browser():
    candidates = [
        # Microsoft Edge (Standard Windows 10/11)
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
        # Google Chrome
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]

    for path in candidates:
        if os.path.isfile(path):
            return path
    return None

def launch_app():
    # 1. Ensure backend is running
    backend_proc = start_backend()

    # 2. Launch browser in standalone app mode
    browser = find_browser()
    flags = CREATE_NO_WINDOW if os.name == "nt" else 0

    if browser:
        cmd = [
            browser,
            f"--app={APP_URL}",
            "--window-size=1440,920",
            "--window-position=80,40"
        ]
        browser_proc = subprocess.Popen(cmd, creationflags=flags)
        
        # If we started our own backend process, keep it alive while the window is open
        if backend_proc:
            try:
                browser_proc.wait()
            except KeyboardInterrupt:
                pass
            finally:
                try:
                    backend_proc.terminate()
                except Exception:
                    pass
    else:
        # Fallback to default browser
        webbrowser.open(APP_URL)
        if backend_proc:
            try:
                while is_backend_running():
                    time.sleep(2)
            except KeyboardInterrupt:
                backend_proc.terminate()

def main():
    launch_app()

if __name__ == "__main__":
    main()
