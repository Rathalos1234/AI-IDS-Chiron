#!/usr/bin/env python3
import os
import signal
import subprocess
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import messagebox
import time

########## IMPORTANT ##########
# Ctrl + C doesn't actually stop the backends so you have to go kill all that stuff manually
# Idk how to fix it tbh
# If you pressed Ctrl + C everything other than the actual launcher itself will keep running

########## To FIX do this (on Mac) ##########
# pkill -f "Chiron/web/node_modules/.bin/vite"
# sudo lsof -ti tcp:5050 | xargs kill -9

SCRIPT_DIR = Path(__file__).resolve().parent
AI_IDS_BACKEND_DIR = SCRIPT_DIR / "AI-IDS"
UNIFIED_FRONTEND_DIR = SCRIPT_DIR / "Chiron" / "web"

# IMPORTANT - THis is using python3 directly (not 'make api') to skip REQUIRE_AUTH for easier integration
# If you want to turn on auth change to: ["make", "api"]
AI_IDS_BACKEND_CMD = ["python3", "api.py"]
UNIFIED_FRONTEND_CMD = ["npm", "run", "dev"]
UNIFIED_APP_URL = "http://localhost:5173"

# ========= INTERNAL STATE =========

backend_proc: subprocess.Popen | None = None
frontend_proc: subprocess.Popen | None = None
root: tk.Tk | None = None


def _start_server(name: str, cwd: Path, command: list[str], proc_name: str):
    """
    Start a dev server in its own process group (so we can kill it cleanly later).
    Does NOT open the browser.
    """
    global backend_proc, frontend_proc

    if not cwd.exists():
        messagebox.showerror("Error", f"{name} directory does not exist:\n{cwd}")
        return

    proc = backend_proc if proc_name == "backend" else frontend_proc

    # Start process if not already running
    if proc is None or proc.poll() is not None:
        try:
            new_proc = subprocess.Popen(
                command,
                cwd=str(cwd),
                start_new_session=True,
            )
            if proc_name == "backend":
                backend_proc = new_proc
            else:
                frontend_proc = new_proc
        except FileNotFoundError as e:
            messagebox.showerror(
                "Error",
                f"Failed to start {name}.\n"
                f"Command: {' '.join(command)}\n"
                f"Error: {e}\n\n"
                "Make sure the tools (python3/npm) are installed.",
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start {name}:\n{e}")

def start_all_servers():
    """Start backend and frontend launcher opens."""
    _start_server("AI-IDS Backend", AI_IDS_BACKEND_DIR, AI_IDS_BACKEND_CMD, "backend")
    _start_server("Unified Frontend", UNIFIED_FRONTEND_DIR, UNIFIED_FRONTEND_CMD, "frontend")

def open_unified_app():
    """Open in browser."""
    webbrowser.open(UNIFIED_APP_URL)

def _ppid_map() -> dict[int, list[int]]:
    """
    Build a mapping of parent pid -> list of child pids.
    Works on Unix (ps) and Windows (wmic). Returns empty dict on failure.
    """
    try:
        if os.name == 'nt':
            out = subprocess.check_output(['wmic', 'process', 'get', 'ParentProcessId,ProcessId'], text=True, stderr=subprocess.DEVNULL)
            mp: dict[int, list[int]] = {}
            lines = out.splitlines()
            # Skip header line(s)
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                try:
                    ppid = int(parts[0])
                    pid = int(parts[1])
                except ValueError:
                    continue
                mp.setdefault(ppid, []).append(pid)
            return mp

        out = subprocess.check_output(["ps", "-axo", "pid=,ppid="], text=True)
    except Exception:
        return {}
    mp: dict[int, list[int]] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            pid = int(parts[0])
            ppid = int(parts[1])
        except ValueError:
            continue
        mp.setdefault(ppid, []).append(pid)
    return mp


def _descendants(root_pid: int) -> list[int]:
    mp = _ppid_map()
    stack = [root_pid]
    out: list[int] = []
    seen = {root_pid}
    while stack:
        p = stack.pop()
        for c in mp.get(p, []):
            if c in seen:
                continue
            seen.add(c)
            out.append(c)
            stack.append(c)
    return out


def _kill_pid(pid: int, sig: int):
    try:
        if os.name == 'nt':
            # Use taskkill to aggressively kill a pid and its children on Windows
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # Only send signal on Unix systems
            if hasattr(signal, 'SIGKILL') and sig == signal.SIGKILL:
                os.kill(pid, signal.SIGKILL)
            else:
                os.kill(pid, sig)
    except Exception:
        pass


def _kill_proc_group(proc: subprocess.Popen | None):
    """Kill the whole process group for a dev server, if it's running."""
    if proc is None:
        return
    if proc.poll() is not None:
        return

    pids = []
    try:
        pids = _descendants(proc.pid)
    except Exception:
        pids = []
    pids.append(proc.pid)

    pgid = None
    if os.name != 'nt':
        try:
            pgid = os.getpgid(proc.pid)
        except Exception:
            pgid = None

    if pgid is not None and os.name != 'nt':
        try:
            os.killpg(pgid, signal.SIGINT)
        except Exception:
            pass
    else:
        # On Windows, best-effort stop the process tree quickly
        if os.name == 'nt':
            try:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    # Fallback iteration for any remaining pids
    for pid in pids:
        _kill_pid(pid, signal.SIGINT)

    for _ in range(30):
        if proc.poll() is not None:
            return
        time.sleep(0.1)

    if pgid is not None and os.name != 'nt':
        try:
            os.killpg(pgid, signal.SIGTERM)
        except Exception:
            pass
    else:
        if os.name == 'nt':
            try:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    for pid in pids:
        _kill_pid(pid, signal.SIGTERM)

    for _ in range(20):
        if proc.poll() is not None:
            return
        time.sleep(0.1)

    if pgid is not None and os.name != 'nt':
        try:
            os.killpg(pgid, signal.SIGKILL)
        except Exception:
            pass
    else:
        if os.name == 'nt':
            try:
                subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

    for pid in pids:
        if os.name != 'nt':
            _kill_pid(pid, signal.SIGKILL)
        else:
            _kill_pid(pid, signal.SIGTERM)

    try:
        proc.wait(timeout=1)
    except Exception:
        pass

def cleanup_servers():
    """Clean up all running servers."""
    global backend_proc, frontend_proc
    _kill_proc_group(backend_proc)
    _kill_proc_group(frontend_proc)
    backend_proc = None
    frontend_proc = None


def on_close(r: tk.Tk | None):
    """Terminate dev servers when the launcher closes."""
    if r is None:
        return
    if messagebox.askokcancel("Quit", "Close launcher and stop servers?"):
        cleanup_servers()
        r.destroy()


def signal_handler(signum, frame):
    """Handle Ctrl+C and other termination signals."""
    print("\nReceived interrupt signal. Shutting down servers...")
    cleanup_servers()
    global root
    if root is not None:
        try:
            root.quit()
        except Exception:
            pass
        try:
            root.destroy()
        except Exception:
            pass
    os._exit(0)


def main():
    global root
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    root = tk.Tk()
    root.title("Capstone Launcher")
    root.geometry("350x160")
    title = tk.Label(root, text="Unified UI", font=("Helvetica", 14, "bold"))
    title.pack(pady=15)
    btn_open = tk.Button(
        root,
        text="Open Application",
        width=25,
        height=2,
        bg="#2563eb",
        fg="white",
        font=("Helvetica", 12, "bold"),
        command=open_unified_app
    )

    btn_open.pack(pady=10)
    info = tk.Label(
        root,
        text="Backend and frontend start automatically.\nClick above to open the unified webui.",
        justify="center",
        font=("Helvetica", 9),
        fg="#666"
    )

    info.pack(pady=10)
    start_all_servers()
    root.protocol("WM_DELETE_WINDOW", lambda: on_close(root))
    try:
        root.mainloop()
    except KeyboardInterrupt:
        signal_handler(signal.SIGINT, None)
    finally:
        cleanup_servers()

if __name__ == "__main__":
    main()

