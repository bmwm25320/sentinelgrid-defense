"""
SentinelGrid Defense - Dedicated Desktop Window & System Tray Launcher
Kaspersky-Grade Native Desktop Window & Real-Time EDR Guardian Service
"""
import os
import sys
import time
import socket
import threading
import multiprocessing
import urllib.request
import traceback

multiprocessing.freeze_support()

# Safeguard stdio when running under windowed mode (console=False in PyInstaller)
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w')

APPDATA_DIR = os.environ.get("APPDATA") or os.path.expanduser("~")
LOG_DIR = os.path.join(APPDATA_DIR, "SentinelGridDefense")
os.makedirs(LOG_DIR, exist_ok=True)
CRASH_LOG = os.path.join(LOG_DIR, "launcher_debug.log")

def log_debug(msg: str):
    try:
        with open(CRASH_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
            f.flush()
    except Exception:
        pass

log_debug(f"Module initialized. sys.executable={sys.executable}, argv={sys.argv}")

try:
    log_debug("Importing PIL...")
    from PIL import Image, ImageDraw
    log_debug("Importing webview...")
    import webview
    log_debug("Imported webview successfully.")
except Exception as e:
    log_debug(f"Import error: {e}\n{traceback.format_exc()}")

# Configure webview settings for modern desktop security & downloads
webview.settings["ALLOW_DOWNLOADS"] = True

def patch_edgechromium_popups():
    try:
        log_debug("Attempting EdgeChromium popup patch...")
        from webview.platforms import edgechromium
        orig_on_new_window = edgechromium.EdgeChrome.on_new_window_request

        def custom_on_new_window_request(self, sender, args):
            uri = str(args.get_Uri()).lower() if args.get_Uri() else ""
            try:
                features = args.get_WindowFeatures()
                has_size = features.get_HasSize() if features else False
            except Exception:
                has_size = False

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

            if webview.settings.get("OPEN_EXTERNAL_LINKS_IN_BROWSER", True):
                import webbrowser
                args.set_Handled(True)
                webbrowser.open(str(args.get_Uri()))
            else:
                orig_on_new_window(self, sender, args)

        edgechromium.EdgeChrome.on_new_window_request = custom_on_new_window_request
        log_debug("EdgeChromium popup patch applied successfully.")
    except Exception as e:
        log_debug(f"EdgeChromium popup patch note: {e}")

# Add backend directory to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

APP_URL = "http://127.0.0.1:8000"

def is_port_in_use(port: int = 8000) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except Exception:
        return False

def wait_for_health(timeout: float = 8.0) -> bool:
    start = time.time()
    url = f"{APP_URL}/api/health"
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=0.3) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.08)
    return False

def create_dual_stack_socket(port: int = 8000):
    """
    Creates a dual-stack socket bound to :: with IPV6_V6ONLY=0,
    enabling simultaneous IPv4 (127.0.0.1) and IPv6 (::1 localhost) connections.
    """
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.bind(('::', port))
        s.listen(128)
        return s
    except Exception:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', port))
        s.listen(128)
        return s

def run_uvicorn():
    log_debug("run_uvicorn() started.")
    try:
        import uvicorn
        log_debug("uvicorn imported successfully.")
        app = None
        try:
            log_debug("attempting from backend.engine import app...")
            from backend.engine import app
            log_debug(f"backend.engine imported, app={app}")
        except Exception as e1:
            log_debug(f"from backend.engine import app failed: {e1}")
            try:
                log_debug("attempting from engine import app...")
                from engine import app
                log_debug(f"engine imported, app={app}")
            except Exception as e2:
                log_debug(f"from engine import app failed: {e2}")
                import importlib.util
                engine_candidates = [
                    os.path.join(BASE_DIR, "engine.py"),
                    os.path.join(BASE_DIR, "backend", "engine.py"),
                    os.path.join(getattr(sys, '_MEIPASS', ''), "backend", "engine.py"),
                    os.path.join(getattr(sys, '_MEIPASS', ''), "engine.py"),
                    os.path.join(os.path.dirname(sys.executable), "backend", "engine.py"),
                    os.path.join(os.path.dirname(sys.executable), "_internal", "backend", "engine.py"),
                    os.path.join(os.path.dirname(sys.executable), "_internal", "engine.py"),
                ]
                for c in engine_candidates:
                    log_debug(f"checking candidate engine file: {c} exists={os.path.exists(c)}")
                    if os.path.exists(c):
                        try:
                            spec = importlib.util.spec_from_file_location("engine", c)
                            mod = importlib.util.module_from_spec(spec)
                            spec.loader.exec_module(mod)
                            app = getattr(mod, "app", None)
                            if app:
                                log_debug(f"Loaded engine app from {c}")
                                break
                        except Exception as e_cand:
                            log_debug(f"Failed loading from candidate {c}: {e_cand}")
        log_debug(f"Resolved app: {app}")
        if app:
            try:
                log_debug("Attempting dual-stack socket on port 8000...")
                sock = create_dual_stack_socket(8000)
                config = uvicorn.Config(app, log_level="warning")
                server = uvicorn.Server(config)
                log_debug("Running uvicorn.Server...")
                server.run(sockets=[sock])
            except Exception as se:
                log_debug(f"Dual-stack failed ({se}), falling back to 0.0.0.0:8000")
                uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
        else:
            log_debug("Engine app could not be resolved in any candidate paths!")
    except Exception as e:
        log_debug(f"Error in run_uvicorn: {e}\n{traceback.format_exc()}")

def get_tray_icon_image():
    # Look for existing icon
    candidates = [
        os.path.join(BASE_DIR, "sentinelgrid.ico"),
        os.path.join(BASE_DIR, "..", "sentinelgrid.ico"),
        os.path.join(getattr(sys, '_MEIPASS', ''), "sentinelgrid.ico"),
        os.path.join(os.path.dirname(sys.executable), "sentinelgrid.ico"),
        os.path.join(os.path.dirname(sys.executable), "_internal", "sentinelgrid.ico"),
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
    log_debug("main() invoked.")
    try:
        # 1. Start backend server thread if not already healthy
        if is_port_in_use(8000) and wait_for_health(timeout=0.4):
            log_debug("Port 8000 already healthy.")
        else:
            log_debug("Port 8000 not active, starting server thread...")
            server_thread = threading.Thread(target=run_uvicorn, daemon=True)
            server_thread.start()
            h_ok = wait_for_health(timeout=10.0)
            log_debug(f"Health check wait result: {h_ok}")

        # 2. Setup native pywebview window
        patch_edgechromium_popups()
        log_debug(f"Creating webview window for {APP_URL}...")
        window = webview.create_window(
            "SentinelGrid Defense",
            APP_URL,
            width=1280,
            height=820,
            min_size=(1024, 680),
            background_color="#070B12"
        )
    except Exception as e:
        log_debug(f"Error initializing window: {e}\n{traceback.format_exc()}")
        return

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

    def summon_gemini_copilot():
        try:
            req = urllib.request.Request(
                f"{APP_URL}/api/gemini/summon",
                data=b"{}",
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            urllib.request.urlopen(req, timeout=2).close()
        except Exception:
            pass
        show_dashboard()

    def register_windows_gemini_hotkey():
        """Registers global Ctrl+Shift+G hotkey so Gemini can be summoned from any Windows app."""
        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            MOD_CONTROL = 0x0002
            MOD_SHIFT = 0x0004
            VK_G = 0x47
            HOTKEY_ID = 9001
            if not user32.RegisterHotKey(None, HOTKEY_ID, MOD_CONTROL | MOD_SHIFT, VK_G):
                log_debug("Ctrl+Shift+G hotkey already registered or unavailable.")
                return
            log_debug("Global Windows hotkey Ctrl+Shift+G registered for Background Gemini Co-Pilot.")
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) != 0:
                if msg.message == 0x0312 and msg.wParam == HOTKEY_ID:  # WM_HOTKEY
                    summon_gemini_copilot()
        except Exception as hk_err:
            log_debug(f"Global hotkey listener note: {hk_err}")

    threading.Thread(target=register_windows_gemini_hotkey, daemon=True).start()

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
            item("Ask Gemini Co-Pilot (Ctrl+Shift+G)", lambda: summon_gemini_copilot()),
            item("Run Quick Smart Scan", lambda: run_quick_scan()),
            pystray.Menu.SEPARATOR,
            item("Exit SentinelGrid", on_exit)
        )

        tray = pystray.Icon("SentinelGridDefense", icon_img, "SentinelGrid Defense Suite", menu)
        tray.run_detached()
    except Exception:
        pass

    # 4. Start webview on main thread with persistent user data directory (disabling InPrivate mode so Google OAuth and session state persist)
    appdata_dir = os.environ.get("APPDATA") or os.path.expanduser("~")
    storage_dir = os.path.join(appdata_dir, "SentinelGridDefense", "webview_cache")
    try:
        os.makedirs(storage_dir, exist_ok=True)
    except Exception:
        pass

    try:
        webview.start(private_mode=False, storage_path=storage_dir)
    except Exception:
        import webbrowser
        webbrowser.open(APP_URL)
        while True:
            time.sleep(1)

log_debug(f"Reached module end. __name__={__name__}")
if __name__ in ("__main__", "__mp_main__"):
    log_debug("Calling main()...")
    try:
        main()
    except Exception as e:
        log_debug(f"Unhandled exception in main: {e}\n{traceback.format_exc()}")
