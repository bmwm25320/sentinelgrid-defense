"""
SentinelGrid Defense - Dedicated Desktop Window & System Tray Launcher
Kaspersky-Grade Native Desktop Window & Real-Time EDR Guardian Service
"""
import os
import sys
import time
import socket
import threading
import urllib.request
from PIL import Image, ImageDraw
import webview

# Configure webview settings for modern desktop security & downloads
webview.settings["ALLOW_DOWNLOADS"] = True

# Patch Edge Chromium popup handling on Windows so Google OAuth signInWithPopup opens in a
# native child WebView2 window sharing the CoreWebView2Environment and cookies/storage.
# This prevents window.close() from closing or blanking the main application window.
try:
    from webview.platforms import edgechromium
    orig_on_new_window = edgechromium.EdgeChrome.on_new_window_request

    def custom_on_new_window_request(self, sender, args):
        uri = str(args.get_Uri()).lower() if args.get_Uri() else ""
        features = args.get_WindowFeatures()
        has_size = features.get_HasSize() if features else False

        # If it is a Google OAuth popup, Firebase auth handler, or popup with dimensions:
        # Let WebView2 open a native child popup window sharing the session and opener.
        if (
            "accounts.google.com" in uri or
            "firebaseapp.com" in uri or
            "google.com" in uri or
            has_size or
            uri == "about:blank" or
            not uri
        ):
            args.set_Handled(False)
            return

        # For external links (e.g. documentation, github repository), open in default external browser
        if webview.settings.get("OPEN_EXTERNAL_LINKS_IN_BROWSER", True):
            import webbrowser
            args.set_Handled(True)
            webbrowser.open(str(args.get_Uri()))
        else:
            orig_on_new_window(self, sender, args)

    edgechromium.EdgeChrome.on_new_window_request = custom_on_new_window_request
except Exception as e:
    print(f"EdgeChromium popup handling initialization note: {e}")

# Add backend directory to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

APP_URL = "http://localhost:8000"

def is_port_in_use(port: int = 8000) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(('127.0.0.1', port)) == 0

def wait_for_health(timeout: float = 12.0) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        for url in [f"{APP_URL}/api/health", "http://127.0.0.1:8000/api/health"]:
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=1.0) as resp:
                    if resp.status == 200:
                        return True
            except Exception:
                pass
        time.sleep(0.2)
    return False

def run_uvicorn():
    try:
        import uvicorn
        app = None
        try:
            from backend.engine import app
        except ImportError:
            try:
                from engine import app
            except ImportError:
                import importlib.util
                engine_candidates = [
                    os.path.join(BASE_DIR, "engine.py"),
                    os.path.join(BASE_DIR, "backend", "engine.py"),
                    os.path.join(getattr(sys, '_MEIPASS', ''), "backend", "engine.py"),
                    os.path.join(getattr(sys, '_MEIPASS', ''), "engine.py"),
                ]
                for c in engine_candidates:
                    if os.path.exists(c):
                        spec = importlib.util.spec_from_file_location("engine", c)
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)
                        app = getattr(mod, "app", None)
                        break
        if app:
            uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
        else:
            print("Engine app could not be resolved.")
    except Exception as e:
        print(f"Error starting engine: {e}")

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
    # 1. Start backend server thread if not already healthy
    if not wait_for_health(timeout=1.0):
        if not is_port_in_use(8000):
            server_thread = threading.Thread(target=run_uvicorn, daemon=True)
            server_thread.start()
        # Wait until /api/health responds
        wait_for_health(timeout=10.0)

    # 2. Setup native pywebview window
    window = webview.create_window(
        "SentinelGrid Defense",
        APP_URL,
        width=1280,
        height=820,
        min_size=(1024, 680),
        background_color="#090d16"
    )

    # State flag to distinguish between user clicking 'X' (minimize to tray) vs 'Exit SentinelGrid' (full shutdown)
    is_shutting_down = False

    def on_closing():
        if is_shutting_down:
            return True
        try:
            window.hide()
        except Exception:
            pass
        return False

    window.events.closing += on_closing

    def show_dashboard():
        try:
            window.show()
            window.restore()
        except Exception:
            pass

    def run_quick_scan():
        try:
            req = urllib.request.Request(
                f"{APP_URL}/api/scan/smart",
                data=b"{}",
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                pass
        except Exception:
            pass
        show_dashboard()

    def on_exit(icon=None, item=None):
        nonlocal is_shutting_down
        is_shutting_down = True
        try:
            if icon:
                icon.stop()
        except Exception:
            pass
        try:
            if window:
                window.destroy()
        except Exception:
            pass
        os._exit(0)

    # 3. System tray integration via pystray (detached background thread)
    try:
        import pystray
        from pystray import MenuItem as item

        icon_img = get_tray_icon_image()

        menu = pystray.Menu(
            item("SentinelGrid Defense v1.0.4", lambda: None, enabled=False),
            item("Protection: Active (ARMED)", lambda: None, enabled=False),
            pystray.Menu.SEPARATOR,
            item("Open Security Dashboard", lambda: show_dashboard(), default=True),
            item("Run Quick Smart Scan", lambda: run_quick_scan()),
            pystray.Menu.SEPARATOR,
            item("Exit SentinelGrid", on_exit)
        )

        tray = pystray.Icon("SentinelGridDefense", icon_img, "SentinelGrid Defense Suite", menu)
        tray.run_detached()
    except Exception as e:
        print(f"System tray warning: {e}")

    # 4. Start webview on main thread with persistent user data directory (disabling InPrivate mode so Google OAuth and session state persist)
    appdata_dir = os.environ.get("APPDATA") or os.path.expanduser("~")
    storage_dir = os.path.join(appdata_dir, "SentinelGridDefense", "webview_cache")
    try:
        os.makedirs(storage_dir, exist_ok=True)
    except Exception:
        pass

    try:
        webview.start(private_mode=False, storage_path=storage_dir)
    except Exception as e:
        print(f"Native webview fallback: {e}")
        import webbrowser
        webbrowser.open(APP_URL)
        while True:
            time.sleep(1)

if __name__ == "__main__":
    main()
