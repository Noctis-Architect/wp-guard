"""WP Guard Windows entry point for PyInstaller builds."""

from __future__ import annotations

import os
import sys


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _setup_paths() -> None:
    if getattr(sys, "frozen", False):
        app_data = os.path.join(
            os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
            "WPGuard",
        )
        os.makedirs(app_data, exist_ok=True)
        os.environ.setdefault("WPGUARD_DATA_DIR", app_data)

        env_file = os.path.join(app_data, ".env")
        if not os.path.exists(env_file):
            bundled_example = os.path.join(sys._MEIPASS, ".env.example")
            if os.path.exists(bundled_example):
                import shutil

                shutil.copy2(bundled_example, env_file)
            else:
                with open(env_file, "w", encoding="utf-8") as handle:
                    handle.write("WP_SCANNER_PORT=5000\n")
        return

    root = _project_root()
    if root not in sys.path:
        sys.path.insert(0, root)
    os.chdir(root)


def main() -> None:
    _setup_paths()

    import eventlet

    eventlet.monkey_patch()

    import threading
    import time
    import webbrowser

    from app import app, socketio

    def _open_browser(port: int) -> None:
        time.sleep(1.5)
        webbrowser.open(f"http://127.0.0.1:{port}/")

    port = int(os.environ.get("WP_SCANNER_PORT", "5000"))
    if os.environ.get("WPGUARD_OPEN_BROWSER", "1") != "0":
        threading.Thread(target=_open_browser, args=(port,), daemon=True).start()

    print(f"WP Guard running at http://127.0.0.1:{port}/")
    print("Press Ctrl+C to stop.")
    socketio.run(
        app,
        host="127.0.0.1",
        port=port,
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
