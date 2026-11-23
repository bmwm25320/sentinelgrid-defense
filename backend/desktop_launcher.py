"""
SentinelGrid Defense - Desktop System Tray & App Launcher
Kaspersky-Grade Desktop UI & Real-Time EDR Guardian Service
"""
import os
import sys
import time
import socket
import threading
import webbrowser
import urllib.request
from PIL import Image, ImageDraw

# Add backend directory to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

APP_URL = "http://localhost:8000"

def is_port_in_use(port: int = 8000) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) == 0

def run_uvicorn():
    try:
        import uvicorn
        from engine import app
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
    except Exception as e:
        print(f"Error starting engine: {e}")

def open_dashboard():
    webbrowser.open(APP_URL)

def run_quick_scan():
    try:
        req = urllib.request.Request(f"{APP_URL}/api/scan/smart", data=b"{}", headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=3) as resp:
            pass
        open_dashboard()
    except Exception:
        open_dashboard()

def get_tray_icon_image():
    # Look for existing icon
    candidates = [
        os.path.join(BASE_DIR, "sentinelgrid.ico"),
        os.path.join(BASE_DIR, "..", "sentinelgrid.ico"),
        os.path.join(getattr(sys, '_MEIPASS', ''), "sentinelgrid.ico"),
        os.path.join(BASE_DIR, "sentinelgrid.png"),
        os.path.join(BASE_DIR, "..", "sentinelgrid.png"),
    ]
    for c in candidates:
        if os.path.exists(c):
            try:
                return Image.open(c)
            except Exception:
                pass
    
    # Generate fallback emerald shield icon
    img = Image.new("RGBA", (64, 64), color=(0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.polygon([(32, 4), (58, 14), (52, 46), (32, 60), (12, 46), (6, 14)], fill=(16, 185, 129, 255), outline=(5, 150, 105, 255))
    d.polygon([(32, 10), (52, 18), (48, 42), (32, 54), (16, 42), (12, 18)], fill=(6, 78, 59, 255))
    d.line([(32, 14), (32, 50)], fill=(52, 211, 153, 255), width=2)
    return img

def main():
    # 1. Start backend server thread if not already running
    if not is_port_in_use(8000):
        server_thread = threading.Thread(target=run_uvicorn, daemon=True)
        server_thread.start()
        
        # Wait until port responds (up to 4s)
        for _ in range(20):
            if is_port_in_use(8000):
                break
            time.sleep(0.2)

    # 2. Automatically launch the full dashboard UI in default browser
    open_dashboard()

    # 3. System tray integration via pystray
    try:
        import pystray
        from pystray import MenuItem as item

        icon_img = get_tray_icon_image()

        def on_exit(icon, _):
            icon.stop()
            os._exit(0)

        menu = pystray.Menu(
            item("SentinelGrid Defense v1.0.4", lambda: None, enabled=False),
            item("Protection: Active (ARMED)", lambda: None, enabled=False),
            pystray.Menu.SEPARATOR,
            item("Open Security Dashboard", lambda: open_dashboard(), default=True),
            item("Run Quick Smart Scan", lambda: run_quick_scan()),
            pystray.Menu.SEPARATOR,
            item("Exit SentinelGrid", on_exit)
        )

        tray = pystray.Icon("SentinelGridDefense", icon_img, "SentinelGrid Defense Suite", menu)
        tray.run()
    except Exception as e:
        # If tray fails for any reason, keep thread alive
        while True:
            time.sleep(1)

if __name__ == "__main__":
    main()
