"""Native-window launcher for Stellina Control (macOS / Windows / Linux).

Starts the local Stellina Control server and shows the UI in its own desktop
window via pywebview. If pywebview isn't available it falls back to opening the
default web browser. This file is the entry point PyInstaller bundles into the
.app / .exe (see build_macos.command and build_windows.bat).
"""
import os, sys, time, threading, pathlib

os.environ.setdefault('STELLINA_NO_BROWSER', '1')
BASE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

import app  # noqa: E402  (reuses the server, handlers and telescope logic)
from http.server import ThreadingHTTPServer  # noqa: E402

PORT = int(os.environ.get('STELLINA_PORT', '8766'))
_server = None


def _serve():
    global _server
    _server = ThreadingHTTPServer(('127.0.0.1', PORT), app.Handler)
    threading.Thread(target=app.idle_cleanup, daemon=True).start()
    _server.serve_forever()


def _wait_ready(url, tries=120):
    import urllib.request
    for _ in range(tries):
        try:
            urllib.request.urlopen(url + '/api/info', timeout=1)
            return True
        except Exception:
            time.sleep(0.1)
    return False


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--set-diag-password':
        import getpass, json, hashlib
        pw = getpass.getpass('New diagnostics password (empty = remove lock): ')
        try:
            d = json.loads(app.CONFIG_PATH.read_text(encoding='utf-8'))
        except Exception:
            d = {}
        d['diagnostics_password_sha256'] = hashlib.sha256(pw.encode()).hexdigest() if pw else ''
        app.CONFIG_PATH.write_text(json.dumps(d, indent=2), encoding='utf-8')
        print('Saved to', app.CONFIG_PATH, '- Diagnostics are now', 'LOCKED.' if pw else 'OPEN.')
        return
    threading.Thread(target=_serve, daemon=True).start()
    url = 'http://127.0.0.1:%d' % PORT
    _wait_ready(url)
    try:
        import webview
        webview.create_window('Stellina Control', url, width=1200, height=880, min_size=(900, 600))
        webview.start()   # blocks until the window is closed
    except Exception:
        import webbrowser
        webbrowser.open(url)
        print('Stellina Control is running at ' + url + '  (close this window to quit)')
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    finally:
        try:
            app.live_disconnect(); app.close_ftp()
        except Exception:
            pass


if __name__ == '__main__':
    main()
