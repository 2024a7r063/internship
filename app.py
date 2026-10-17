"""
Sentinel — File Integrity Monitoring System
============================================
A beginner-friendly cybersecurity project written in Python.
This program monitors folders on your computer to detect if any files or
folders are ADDED, MODIFIED, or DELETED.

How File Integrity Monitoring Works:
1. Baseline: Record the current state of chosen folders (files, subfolders, and SHA-256 hashes).
2. Scan: Later, scan the folders again and calculate new hashes.
3. Compare: Detect differences:
   - ADDED: New file or folder created.
   - MODIFIED: Existing file content changed (hash mismatch).
   - DELETED: Existing file or folder removed.
   - UNCHANGED: File content matches the baseline exactly.
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote
import datetime
import hashlib
import html
import json
import os

# ------------------------------------------------------------------------------
# 1. Project Configuration & Storage Paths
# ------------------------------------------------------------------------------
# Find the directory where this script is located
PROJECT_DIR = Path(__file__).resolve().parent

# Folder for demo test files
DEMO_DIR = PROJECT_DIR / "demo_files"

# Folder for saving baseline data
DATA_DIR = PROJECT_DIR / "data"

# File where the baseline is saved as JSON
BASELINE_FILE = DATA_DIR / "baseline.json"

# File where temporarily selected folders are remembered
SELECTED_FILE = DATA_DIR / "selected_folders.json"

# Web server settings (runs locally on your PC)
HOST = "127.0.0.1"
PORT = 5000


# ==============================================================================
# 2. SHA-256 Hashing Function
# ==============================================================================

def calculate_sha256(file_path):
    """
    Calculate the SHA-256 digital fingerprint (hash) of a single file.

    A hash is a 64-character text string uniquely representing the file's content.
    If even a single letter in the file changes (like 'hii' to 'bye'), the hash
    changes completely!
    """
    hasher = hashlib.sha256()

    try:
        # Open file in binary read mode ('rb')
        with open(file_path, "rb") as file:
            # Read in chunks of 64KB (65,536 bytes) so large files don't overload memory
            while True:
                chunk = file.read(65536)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError):
        # Return empty string if file cannot be read (e.g. permission denied)
        return ""


# ==============================================================================
# 3. Recursive Folder Scanning (Files & Nested Subfolders)
# ==============================================================================

def scan_folder(folder_path):
    """
    Scan a root folder recursively to find all files and all nested directories.

    Returns:
        dict: {
            "files": { "relative/path/to/file.txt": "sha256_hash", ... },
            "directories": [ "subfolder", "subfolder/nested", ... ],
            "unreadable": [ "protected_file.txt", ... ]
        }
    """
    folder = Path(folder_path).resolve()
    if not folder.exists() or not folder.is_dir():
        return {"files": {}, "directories": [], "unreadable": []}

    files_dict = {}
    directories_list = []
    unreadable_list = []

    # rglob("*") finds every item inside this folder and all nested subfolders
    for item in folder.rglob("*"):
        try:
            # Get path relative to the monitored root folder (e.g. "source/main.py")
            rel_path = str(item.relative_to(folder))

            # 1. Check if the item is a directory (subfolder)
            if item.is_dir():
                directories_list.append(rel_path)

            # 2. Check if the item is a regular file (skip symlinks)
            elif item.is_file() and not item.is_symlink():
                file_hash = calculate_sha256(item)
                if file_hash:
                    files_dict[rel_path] = file_hash
                else:
                    unreadable_list.append(rel_path)

        except (PermissionError, OSError):
            unreadable_list.append(str(item.name))

    return {
        "files": files_dict,
        "directories": directories_list,
        "unreadable": unreadable_list
    }


# ==============================================================================
# 4. Integrity Comparison (Detect Added, Modified, Deleted)
# ==============================================================================

def compare_folder_against_baseline(root_path, saved_files, saved_directories):
    """
    Compare current files and folders on disk against the saved baseline.

    Detects:
    - ADDED: New files or newly created empty/nested folders.
    - MODIFIED: Existing file whose SHA-256 hash changed.
    - DELETED: Files or folders that were in baseline but are now missing.
    - UNCHANGED: Files whose SHA-256 hash matches the baseline exactly.
    """
    current_scan = scan_folder(root_path)
    current_files = current_scan["files"]
    current_dirs_set = set(current_scan["directories"])
    saved_dirs_set = set(saved_directories)

    saved_files_set = set(saved_files.keys())
    current_files_set = set(current_files.keys())

    results = []

    # --------------------------------------------------------------------------
    # Step A: Check Files from the Baseline (Modified, Deleted, Unchanged)
    # --------------------------------------------------------------------------
    for filename in sorted(list(saved_files_set)):
        if filename in current_files_set:
            old_hash = saved_files[filename]
            new_hash = current_files[filename]

            # Compare SHA-256 hashes
            if old_hash != new_hash:
                results.append({
                    "status": "MODIFIED",
                    "item_type": "File",
                    "name": filename,
                    "folder": root_path,
                    "details": "Hash mismatch detected — file contents have changed.",
                    "risk": "Suspicious change — review required",
                    "old_hash": old_hash,
                    "new_hash": new_hash
                })
            else:
                results.append({
                    "status": "UNCHANGED",
                    "item_type": "File",
                    "name": filename,
                    "folder": root_path,
                    "details": "Hash matches baseline exactly.",
                    "risk": "Safe",
                    "old_hash": old_hash,
                    "new_hash": new_hash
                })
        else:
            # File existed in baseline, but does not exist on disk now
            results.append({
                "status": "DELETED",
                "item_type": "File",
                "name": filename,
                "folder": root_path,
                "details": "File missing — removed from disk.",
                "risk": "Potentially suspicious — review required",
                "old_hash": saved_files[filename],
                "new_hash": "None"
            })

    # --------------------------------------------------------------------------
    # Step B: Check for Newly ADDED Files
    # --------------------------------------------------------------------------
    for filename in sorted(list(current_files_set)):
        if filename not in saved_files_set:
            results.append({
                "status": "ADDED",
                "item_type": "File",
                "name": filename,
                "folder": root_path,
                "details": "New file detected.",
                "risk": "Suspicious change — review required",
                "old_hash": "None",
                "new_hash": current_files[filename]
            })

    # --------------------------------------------------------------------------
    # Step C: Check for Newly ADDED Folders (Directories)
    # --------------------------------------------------------------------------
    for dirname in sorted(list(current_dirs_set)):
        if dirname not in saved_dirs_set:
            results.append({
                "status": "ADDED",
                "item_type": "Folder",
                "name": dirname,
                "folder": root_path,
                "details": "New directory detected.",
                "risk": "Suspicious change — review required",
                "old_hash": "-",
                "new_hash": "-"
            })

    # --------------------------------------------------------------------------
    # Step D: Check for DELETED Folders (Directories)
    # --------------------------------------------------------------------------
    for dirname in sorted(list(saved_dirs_set)):
        if dirname not in current_dirs_set:
            results.append({
                "status": "DELETED",
                "item_type": "Folder",
                "name": dirname,
                "folder": root_path,
                "details": "Directory removed from disk.",
                "risk": "Potentially suspicious — review required",
                "old_hash": "-",
                "new_hash": "-"
            })

    return {
        "folder": root_path,
        "results": results,
        "total_files": len(current_files),
        "total_directories": len(current_dirs_set),
        "unreadable": current_scan["unreadable"]
    }


# ==============================================================================
# 5. Baseline JSON Storage (Save & Load)
# ==============================================================================

def load_baselines():
    """
    Load saved baselines from data/baseline.json.
    Returns a list of dicts: [ {"root_path": "...", "files": {...}, "directories": [...]} ]
    """
    if not BASELINE_FILE.exists():
        return []

    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)

        if isinstance(data, dict) and isinstance(data.get("folders"), list):
            clean_list = []
            for item in data["folders"]:
                root = item.get("root_path") or item.get("folder")
                files = item.get("files", {})
                dirs = item.get("directories", [])
                if root:
                    clean_list.append({"root_path": root, "files": files, "directories": dirs})
            return clean_list
        return []
    except Exception:
        return []


def save_baselines(baselines_list):
    """Save all monitored root folders and their baselines into data/baseline.json."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temp_file = BASELINE_FILE.with_suffix(".tmp")
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(temp_file, "w", encoding="utf-8") as file:
        json.dump({
            "created_at": now_str,
            "folders": baselines_list
        }, file, indent=2)

    temp_file.replace(BASELINE_FILE)


# ==============================================================================
# 6. Folder Selection Queue (Select multiple folders before creating baseline)
# ==============================================================================

def load_selected_folders():
    """Load the list of folders the user has selected."""
    if not SELECTED_FILE.exists():
        return []

    try:
        with open(SELECTED_FILE, "r", encoding="utf-8") as file:
            folders = json.load(file)
            if isinstance(folders, list):
                # Filter out folders that no longer exist
                valid_folders = [str(Path(f).resolve()) for f in folders if Path(f).is_dir()]
                return valid_folders
        return []
    except Exception:
        return []


def save_selected_folders(folders_list):
    """Save the selected folders list to data/selected_folders.json."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    clean_list = []
    for f in folders_list:
        norm = str(Path(f).resolve())
        if norm not in clean_list and Path(norm).is_dir():
            clean_list.append(norm)

    with open(SELECTED_FILE, "w", encoding="utf-8") as file:
        json.dump(clean_list, file, indent=2)


def add_selected_folder(folder_path):
    """
    Add a folder to the selected list.
    Validates that the folder exists and prevents duplicates.
    """
    if not folder_path or not folder_path.strip():
        return False, "Please choose or enter a valid folder path."

    p = Path(folder_path.strip()).expanduser().resolve()
    if not p.exists():
        return False, f"Folder does not exist: {p}"
    if not p.is_dir():
        return False, f"Path is a file, not a folder: {p}"

    current = load_selected_folders()
    p_str = str(p)

    # Check for duplicates
    if p_str in current:
        return False, f"Folder is already selected: {p_str}"

    current.append(p_str)
    save_selected_folders(current)
    return True, f"Added folder: {p_str}"


def remove_selected_folder(folder_path):
    """Remove a folder from the selected list."""
    current = load_selected_folders()
    target = str(Path(folder_path).resolve())
    updated = [f for f in current if str(Path(f).resolve()) != target]
    save_selected_folders(updated)


def clear_selected_folders():
    """Clear all selected folders from the queue."""
    save_selected_folders([])


# ==============================================================================
# 7. Native Windows File Explorer Dialog (Tkinter)
# ==============================================================================

def open_windows_folder_dialog():
    """
    Open the real Windows File Explorer folder selection window.
    This lets the user pick any folder from their PC (Documents, Desktop, etc.).

    Returns:
        str: Absolute path of the selected folder, or None if user canceled.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog

        # Create a hidden Tkinter root window
        root = tk.Tk()
        root.withdraw()

        # Bring the dialog window to the front of all windows
        root.attributes("-topmost", True)
        root.focus_force()

        # Open the native Windows folder picker
        selected_folder = filedialog.askdirectory(
            title="Sentinel - Choose a folder to monitor"
        )

        # Destroy the Tkinter window cleanly
        root.destroy()

        if selected_folder:
            return os.path.normpath(selected_folder)
        return None
    except Exception as error:
        print(f"Notice: Could not open Windows dialog ({error})")
        return None


# ==============================================================================
# 8. Web Interface & HTML Rendering (Clean Dark Theme)
# ==============================================================================

def esc(text):
    """Safely escape text for HTML output."""
    return html.escape(str(text), quote=True)


def page_template(body_content, title="Sentinel | File Integrity Monitor"):
    """Wrap content in a clean, modern, beginner-friendly dark layout."""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{esc(title)}</title>
  <style>
    :root {{
      --bg: #0a1020;
      --panel: #111b2e;
      --line: #24354e;
      --text: #eaf1fb;
      --muted: #8ea3bf;
      --cyan: #67d9e8;
      --green: #5de0ac;
      --red: #ff6b81;
      --amber: #ffd080;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: radial-gradient(ellipse at 80% -10%, #152744 0, transparent 45%), var(--bg);
      color: var(--text);
      font: 14px/1.55 "Segoe UI", Arial, sans-serif;
    }}
    .layout {{ display: flex; min-height: 100vh; }}
    .side {{
      width: 235px;
      background: #0b1424;
      border-right: 1px solid var(--line);
      padding: 24px 18px;
      display: flex;
      flex-direction: column;
      flex-shrink: 0;
    }}
    .logo {{ display: flex; align-items: center; gap: 10px; font-weight: 800; letter-spacing: 2px; font-size: 16px; }}
    .mark {{
      display: grid;
      place-items: center;
      width: 36px;
      height: 36px;
      border-radius: 10px;
      background: linear-gradient(135deg, #67d9e8, #6194ff);
      color: #06101e;
      font-size: 20px;
      font-weight: 800;
    }}
    .brand-sub {{ color: var(--muted); font-size: 9px; letter-spacing: 2px; margin: 4px 0 0 46px; }}
    .sidebox {{ margin-top: 24px; border-top: 1px solid var(--line); padding-top: 16px; color: #b8c5d7; font-size: 11px; line-height: 1.6; }}
    .sidefoot {{ margin-top: auto; color: var(--muted); font-size: 10px; padding-top: 20px; border-top: 1px solid var(--line); }}
    .main {{ width: min(1200px, 100%); padding: 28px clamp(16px, 4vw, 40px); margin: 0 auto; }}
    .top {{ display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }}
    .eyebrow {{ font-size: 11px; letter-spacing: 1.5px; color: var(--muted); font-weight: 800; text-transform: uppercase; }}
    h1 {{ font-size: clamp(24px, 3vw, 30px); margin: 6px 0; }}
    h2 {{ font-size: 18px; margin: 4px 0 0; }}
    .sub {{ color: var(--muted); margin: 0; font-size: 13px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 14px; margin-bottom: 20px; }}
    .metric, .panel {{ background: linear-gradient(145deg, #121e32, #101929); border: 1px solid var(--line); border-radius: 12px; }}
    .metric {{ padding: 16px; }}
    .metric-label {{ color: var(--muted); font-size: 10px; letter-spacing: 1px; font-weight: 800; }}
    .metric-value {{ font-size: 26px; font-weight: 800; margin-top: 6px; color: var(--text); }}
    .metric-note {{ color: var(--muted); font-size: 11px; margin-top: 4px; }}
    .panel {{ padding: 22px; margin-bottom: 20px; }}
    .panelhead {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 12px; flex-wrap: wrap; }}
    .copy {{ color: var(--muted); font-size: 13px; line-height: 1.7; margin: 8px 0 16px; }}
    code {{ color: var(--cyan); background: #08111e; padding: 2px 6px; border: 1px solid var(--line); border-radius: 4px; font-family: Consolas, monospace; font-size: 12px; }}
    .buttons {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 14px; }}
    .btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      border: 1px solid transparent;
      border-radius: 8px;
      padding: 10px 16px;
      text-decoration: none;
      font-size: 13px;
      font-weight: 700;
      cursor: pointer;
      font-family: inherit;
      transition: all 0.15s ease;
    }}
    .btn:hover {{ filter: brightness(1.15); }}
    .btn:disabled {{ opacity: 0.45; cursor: not-allowed; }}
    .btn.primary {{ background: var(--cyan); color: #071421; }}
    .btn.success-btn {{ background: var(--green); color: #071421; }}
    .btn.secondary {{ background: #162438; color: #e2ecfa; border-color: #314664; }}
    .btn.danger {{ background: #351d29; color: #ffb0bd; border-color: #704052; }}
    .btn.small {{ padding: 5px 10px; font-size: 11px; }}
    .notice {{ padding: 13px 17px; border-radius: 8px; margin-bottom: 20px; font-size: 13px; }}
    .notice.success {{ background: #102c2a; border: 1px solid #285b4c; color: #9af0cb; }}
    .notice.error {{ background: #351d29; border: 1px solid #704052; color: #ffb0bd; }}
    .notice.info {{ background: #15273f; border: 1px solid #28476d; color: #b4d8ff; }}
    .banner {{ display: flex; gap: 16px; align-items: center; padding: 18px; border-radius: 12px; margin-bottom: 20px; border: 1px solid var(--line); }}
    .banner.good {{ background: #102c2a; border-color: #285b4c; }}
    .banner.bad {{ background: #351d29; border-color: #704052; }}
    .symbol {{ display: grid; place-items: center; flex-shrink: 0; width: 42px; height: 42px; border-radius: 50%; font-size: 22px; font-weight: 800; }}
    .banner.good .symbol {{ background: #1b4b3e; color: var(--green); }}
    .banner.bad .symbol {{ background: #5a2b3c; color: var(--red); }}
    .banner p {{ color: var(--muted); font-size: 13px; margin: 4px 0 0; }}
    .pill {{ padding: 4px 8px; border-radius: 5px; font-size: 10px; font-weight: 800; letter-spacing: 0.5px; display: inline-block; }}
    .pill.MODIFIED {{ color: var(--red); background: #3a202b; border: 1px solid #753545; }}
    .pill.ADDED {{ color: var(--amber); background: #352d20; border: 1px solid #6b552f; }}
    .pill.DELETED {{ color: #ffa3b0; background: #451b24; border: 1px solid #822736; }}
    .pill.UNCHANGED {{ color: var(--green); background: #102c2a; border: 1px solid #285b4c; }}
    .pill.folder-tag {{ color: var(--cyan); background: #13273e; border: 1px solid #22436d; }}
    .folder-list {{ margin-top: 12px; border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: #0c1423; }}
    .folder-row {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 16px; border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }}
    .folder-row:last-child {{ border-bottom: 0; }}
    .folder-info {{ flex: 1; }}
    .folder-info strong {{ font-size: 13px; color: var(--text); }}
    .folder-info small {{ display: block; color: var(--muted); font-size: 11px; margin-top: 3px; }}
    .path-input-group {{ display: flex; gap: 10px; margin-top: 14px; flex-wrap: wrap; }}
    .path-input {{ flex: 1; min-width: 250px; background: #091322; border: 1px solid #354862; border-radius: 8px; padding: 10px 14px; color: var(--text); font-family: inherit; font-size: 13px; }}
    .path-input:focus {{ outline: none; border-color: var(--cyan); }}
    .tablewrap {{ overflow-x: auto; margin-top: 14px; border-radius: 8px; border: 1px solid var(--line); }}
    table {{ border-collapse: collapse; width: 100%; text-align: left; font-size: 12px; background: #0b1322; }}
    th {{ font-size: 10px; letter-spacing: 1px; color: var(--muted); padding: 11px 12px; border-bottom: 1px solid var(--line); background: #0f192b; }}
    td {{ padding: 11px 12px; border-bottom: 1px solid #1a273b; overflow-wrap: anywhere; }}
    tr:last-child td {{ border-bottom: 0; }}
    .hash-val {{ font-family: Consolas, monospace; font-size: 11px; color: var(--cyan); }}
    .footer {{ color: var(--muted); font-size: 11px; padding: 15px 0; }}
    @media (max-width: 850px) {{
      .metrics {{ grid-template-columns: repeat(2, 1fr); }}
    }}
    @media (max-width: 768px) {{
      .layout {{ flex-direction: column; }}
      .side {{ width: 100%; padding: 16px; }}
      .sidebox, .sidefoot, .brand-sub {{ display: none; }}
      .metrics {{ grid-template-columns: 1fr; }}
      .main {{ padding: 20px 14px; }}
    }}
  </style>
</head>
<body>
  <div class="layout">
    <aside class="side">
      <div class="logo"><div class="mark">S</div><div>SENTINEL</div></div>
      <div class="brand-sub">INTEGRITY MONITOR</div>
      <div class="sidebox">
        <strong>LOCAL PC MONITOR</strong>
        <p>Monitors folders on your PC and alerts you if any file is altered, added, or deleted.</p>
      </div>
      <div class="sidefoot">
        <strong>COLLEGE PROJECT</strong><br>
        Pure Python Standard Library<br>
        SHA-256 File Signatures
      </div>
    </aside>
    <main class="main">
      {body_content}
      <div class="footer">Sentinel File Integrity Monitor · All baseline fingerprints saved locally in <code>data/baseline.json</code></div>
    </main>
  </div>
</body>
</html>"""


def render_dashboard(notice_msg="", notice_kind="info"):
    """Generate the main dashboard page."""
    selected_folders = load_selected_folders()
    saved_baselines = load_baselines()

    total_monitored_files = sum(len(b.get("files", {})) for b in saved_baselines)
    total_monitored_dirs = sum(len(b.get("directories", [])) for b in saved_baselines)

    notice_html = f'<div class="notice {notice_kind}">{esc(notice_msg)}</div>' if notice_msg else ""

    # Monitored Folders list
    if saved_baselines:
        saved_rows = []
        for b in saved_baselines:
            root_path = b["root_path"]
            file_count = len(b.get("files", {}))
            dir_count = len(b.get("directories", []))
            saved_rows.append(f"""
            <div class="folder-row">
              <div class="folder-info">
                <strong>📁 {esc(root_path)}</strong>
                <small>{file_count} file(s) and {dir_count} subfolder(s) recorded in baseline</small>
              </div>
              <span class="pill UNCHANGED">MONITORED ROOT</span>
            </div>
            """)
        saved_html = "".join(saved_rows)
    else:
        saved_html = """
        <div class="folder-row" style="color:var(--muted); justify-content:center; padding: 22px;">
          No baseline created yet. Choose folders below and click 'Create Baseline'.
        </div>
        """

    # Selected Folders queue list
    if selected_folders:
        selected_rows = []
        for folder_path in selected_folders:
            folder_name = Path(folder_path).name or folder_path
            selected_rows.append(f"""
            <div class="folder-row">
              <div class="folder-info">
                <strong>📁 {esc(folder_name)}</strong>
                <small>Path: <code>{esc(folder_path)}</code></small>
              </div>
              <form method="post" action="/remove-folder" style="margin:0">
                <input type="hidden" name="folder" value="{esc(folder_path)}">
                <button class="btn danger small" type="submit">✕ Remove</button>
              </form>
            </div>
            """)
        selected_html = "".join(selected_rows)
    else:
        selected_html = """
        <div class="folder-row" style="color:var(--muted); justify-content:center; padding: 18px;">
          No folders selected yet. Click 'Browse for Folder' to select from your PC.
        </div>
        """

    content = f"""
    <div class="top">
      <div>
        <div class="eyebrow">CYBERSECURITY / FILE INTEGRITY</div>
        <h1>Sentinel Dashboard</h1>
        <p class="sub">Select folders from your PC, create a baseline, and scan for unauthorized alterations.</p>
      </div>
      <div class="ready" style="font-size:11px; letter-spacing:1px; border:1px solid #285b4c; background:#102c2a; color:var(--green); padding:8px 14px; border-radius:8px; font-weight:700;">
        <span style="display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--green); margin-right:6px;"></span>SYSTEM READY
      </div>
    </div>

    {notice_html}

    <!-- METRICS OVERVIEW -->
    <section class="metrics">
      <div class="metric">
        <div class="metric-label">MONITORED FOLDERS</div>
        <div class="metric-value">{len(saved_baselines)}</div>
        <div class="metric-note">Root locations in baseline</div>
      </div>
      <div class="metric">
        <div class="metric-label">FILES IN BASELINE</div>
        <div class="metric-value">{total_monitored_files}</div>
        <div class="metric-note">Recorded SHA-256 hashes</div>
      </div>
      <div class="metric">
        <div class="metric-label">SUBDIRECTORIES</div>
        <div class="metric-value">{total_monitored_dirs}</div>
        <div class="metric-note">Nested folders monitored</div>
      </div>
      <div class="metric">
        <div class="metric-label">HASH METHOD</div>
        <div class="metric-value" style="font-size:20px; color:var(--cyan)">SHA-256</div>
        <div class="metric-note">Digital fingerprint standard</div>
      </div>
    </section>

    <!-- SECTION 1: SAVED BASELINE & SCANNING -->
    <section class="panel">
      <div class="panelhead">
        <div>
          <div class="eyebrow">ACTIVE BASELINE</div>
          <h2>Monitored Folders ({len(saved_baselines)})</h2>
        </div>
      </div>
      <p class="copy">
        The baseline represents the known-safe reference state. Click <strong>Scan for Changes</strong>
        to detect if any file was altered, added, or deleted since the baseline was created.
      </p>

      <div class="folder-list">
        {saved_html}
      </div>

      <div class="buttons">
        <form method="post" action="/scan-all" style="margin:0">
          <button class="btn primary" type="submit" {"disabled" if not saved_baselines else ""}>
            🔍 Scan for Changes
          </button>
        </form>
        <form method="post" action="/clear-baseline" onsubmit="return confirm('Are you sure you want to delete all saved baselines?');" style="margin:0">
          <button class="btn danger" type="submit" {"disabled" if not saved_baselines else ""}>
            🗑️ Clear Saved Baseline
          </button>
        </form>
      </div>
    </section>

    <!-- SECTION 2: CHOOSE FOLDERS FROM PC -->
    <section class="panel">
      <div class="panelhead">
        <div>
          <div class="eyebrow">STEP 1: FOLDER SELECTION</div>
          <h2>Choose Folders from Your PC</h2>
        </div>
        <span class="pill UNCHANGED">MULTI-FOLDER SUPPORT</span>
      </div>
      <p class="copy">
        Click <strong>Browse for Folder</strong> to open your computer's native Windows File Explorer dialog.
        You can select multiple folders (e.g. <code>Documents\\Project</code>, <code>Desktop\\Test</code>).
      </p>

      <div class="buttons">
        <!-- Native Windows File Explorer Button -->
        <a class="btn primary" href="/browse-folder" title="Opens the real Windows folder selection dialog">
          📁 Browse for Folder (Open Windows Explorer)
        </a>
        <form method="post" action="/add-demo-folder" style="margin:0">
          <button class="btn secondary" type="submit">⚡ Add Demo Folder</button>
        </form>
      </div>

      <!-- Paste Path Alternative -->
      <form method="post" action="/add-folder-path" class="path-input-group">
        <input class="path-input" type="text" name="folder_path" placeholder="Or paste full folder path here (e.g. C:\\Users\\... or D:\\CollegeProject)">
        <button class="btn secondary" type="submit">+ Add Path</button>
      </form>

      <!-- SELECTED FOLDERS QUEUE -->
      <div style="margin-top:22px;">
        <div class="panelhead">
          <div>
            <div class="eyebrow">STEP 2: CONFIRM SELECTION</div>
            <h2>Selected Folders ({len(selected_folders)})</h2>
          </div>
        </div>
        <p class="copy">
          These folders will be included in the baseline snapshot. Check the list and click <strong>Create Baseline</strong>.
        </p>

        <div class="folder-list">
          {selected_html}
        </div>

        <div class="buttons">
          <form method="post" action="/create-baseline" onsubmit="{ 'return confirm(\"A baseline already exists. Do you want to overwrite it with this new selection?\");' if saved_baselines else 'return true;' }" style="margin:0">
            <button class="btn success-btn" type="submit" {"disabled" if not selected_folders else ""}>
              🚀 Create Baseline for Selected Folders ({len(selected_folders)})
            </button>
          </form>
          <form method="post" action="/clear-selection" style="margin:0">
            <button class="btn secondary" type="submit" {"disabled" if not selected_folders else ""}>
              Clear Selection
            </button>
          </form>
        </div>
      </div>
    </section>

    <!-- SECTION 3: EDUCATIONAL TESTING GUIDE -->
    <section class="panel">
      <div class="eyebrow">HOW TO TEST & EXPLAIN TO YOUR TEACHER</div>
      <h2>How Sentinel Detects Alterations</h2>
      <div class="folder-list">
        <div class="folder-row">
          <div class="folder-info">
            <strong>1. Select a folder & click 'Create Baseline'</strong>
            <small>Sentinel scans every file and nested subfolder, computes a SHA-256 fingerprint, and saves it in <code>data/baseline.json</code>.</small>
          </div>
        </div>
        <div class="folder-row">
          <div class="folder-info">
            <strong>2. Edit any file on your computer & save (Ctrl + S)</strong>
            <small>Open any monitored file in Notepad, change text (e.g. 'hii how are you' to 'bye'), and save with <code>Ctrl + S</code>.</small>
          </div>
        </div>
        <div class="folder-row">
          <div class="folder-info">
            <strong>3. Click 'Scan for Changes'</strong>
            <small>Sentinel recalculates current hashes. Because the text changed, the hash differs -> Sentinel flags it as <strong>MODIFIED (Hash mismatch)</strong>!</small>
          </div>
        </div>
      </div>
    </section>
    """
    return page_template(content)


def render_scan_results(reports):
    """
    Generate the scan results report page matching all table columns and metrics:
    - Status (ADDED, MODIFIED, DELETED, UNCHANGED)
    - Item Type (File or Folder)
    - Name or Path
    - Monitored Folder
    - Details (Hash mismatch, new file, file missing, etc.)
    - Risk (Suspicious change / Safe)
    """
    total_root_folders = len(reports)
    total_files = sum(r["total_files"] for r in reports)
    total_dirs = sum(r["total_directories"] for r in reports)
    total_unreadable = sum(len(r["unreadable"]) for r in reports)

    # Flatten all results
    all_items = []
    for r in reports:
        all_items.extend(r["results"])

    added_items = [item for item in all_items if item["status"] == "ADDED"]
    modified_items = [item for item in all_items if item["status"] == "MODIFIED"]
    deleted_items = [item for item in all_items if item["status"] == "DELETED"]
    unchanged_items = [item for item in all_items if item["status"] == "UNCHANGED"]

    total_changes = len(added_items) + len(modified_items) + len(deleted_items)

    # Status banner
    if total_changes == 0:
        banner_html = """
        <section class="banner good">
          <div class="symbol">✓</div>
          <div>
            <div class="eyebrow">INTEGRITY VERIFIED · ALL SECURE</div>
            <h2>All Files & Folders Match Baseline Exactly</h2>
            <p>Every monitored file and directory matches its baseline SHA-256 fingerprint. Zero unauthorized modifications detected.</p>
          </div>
        </section>
        """
    else:
        summary_parts = []
        if modified_items: summary_parts.append(f"{len(modified_items)} MODIFIED file(s)")
        if added_items: summary_parts.append(f"{len(added_items)} ADDED item(s)")
        if deleted_items: summary_parts.append(f"{len(deleted_items)} DELETED item(s)")
        banner_html = f"""
        <section class="banner bad">
          <div class="symbol">!</div>
          <div>
            <div class="eyebrow">INTEGRITY ALERT · DISCREPANCIES DETECTED</div>
            <h2>⚠️ {total_changes} Change(s) Detected!</h2>
            <p><strong>{' · '.join(summary_parts)}</strong>. Review the detailed audit log below. A change may be legitimate or unauthorized.</p>
          </div>
        </section>
        """

    # Build Results Table Rows
    table_rows = []
    # Show changes first (Modified, Added, Deleted), then Unchanged
    sorted_items = modified_items + added_items + deleted_items + unchanged_items

    for item in sorted_items:
        status = item["status"]
        item_type = item["item_type"]
        name = item["name"]
        root_folder = Path(item["folder"]).name or item["folder"]
        details = item["details"]
        risk = item["risk"]

        # Extra hash info for modified files
        hash_info = ""
        if status == "MODIFIED":
            hash_info = f"""
            <div style="margin-top:4px; font-size:11px;">
              <span style="color:var(--muted)">Previous SHA-256:</span> <code class="hash-val">{esc(item['old_hash'][:16])}...</code><br>
              <span style="color:var(--red)">Current SHA-256:</span> <code class="hash-val">{esc(item['new_hash'][:16])}...</code>
            </div>
            """
        elif status == "ADDED" and item_type == "File":
            hash_info = f"""
            <div style="margin-top:4px; font-size:11px;">
              <span style="color:var(--amber)">SHA-256:</span> <code class="hash-val">{esc(item['new_hash'][:16])}...</code>
            </div>
            """

        row_bg = ""
        if status == "MODIFIED": row_bg = 'style="background:#26141c;"'
        elif status == "ADDED": row_bg = 'style="background:#241d13;"'
        elif status == "DELETED": row_bg = 'style="background:#2a1318;"'

        table_rows.append(f"""
        <tr {row_bg}>
          <td><span class="pill {status}">{status}</span></td>
          <td><span class="pill folder-tag">{item_type}</span></td>
          <td><strong>{esc(name)}</strong></td>
          <td style="color:var(--muted); font-size:11px;">📁 {esc(root_folder)}</td>
          <td>
            {esc(details)}
            {hash_info}
          </td>
          <td style="font-weight:700; color:{'var(--red)' if 'Suspicious' in risk else ('var(--green)' if risk == 'Safe' else 'var(--amber)')};">
            {esc(risk)}
          </td>
        </tr>
        """)

    if not table_rows:
        table_rows.append('<tr><td colspan="6" style="text-align:center; color:var(--muted); padding:20px;">No monitored items found.</td></tr>')

    content = f"""
    <div class="top">
      <div>
        <div class="eyebrow">INTEGRITY AUDIT REPORT</div>
        <h1>Scan Results</h1>
        <p class="sub">Audited {total_root_folders} root folder(s), {total_files} file(s), and {total_dirs} directory/directories.</p>
      </div>
      <a class="btn secondary" href="/">← Return to Dashboard</a>
    </div>

    {banner_html}

    <!-- METRICS SUMMARY -->
    <section class="metrics">
      <div class="metric">
        <div class="metric-label">MONITORED FOLDERS</div>
        <div class="metric-value">{total_root_folders}</div>
        <div class="metric-note">Root locations scanned</div>
      </div>
      <div class="metric">
        <div class="metric-label">TOTAL FILES SCANNED</div>
        <div class="metric-value">{total_files}</div>
        <div class="metric-note">Across all subfolders</div>
      </div>
      <div class="metric">
        <div class="metric-label">DIRECTORIES SCANNED</div>
        <div class="metric-value">{total_dirs}</div>
        <div class="metric-note">Subfolders checked</div>
      </div>
      <div class="metric">
        <div class="metric-label">TOTAL CHANGES</div>
        <div class="metric-value" style="color:{'var(--red)' if total_changes else 'var(--green)'}">{total_changes}</div>
        <div class="metric-note">{len(modified_items)} mod / {len(added_items)} add / {len(deleted_items)} del</div>
      </div>
    </section>

    <!-- AUDIT BREAKDOWN TABLE -->
    <section class="panel">
      <div class="panelhead">
        <div>
          <div class="eyebrow">AUDIT DETAILS</div>
          <h2>Item Breakdown Table ({len(all_items)} items)</h2>
        </div>
        <div>
          <span class="pill MODIFIED">{len(modified_items)} Modified</span>
          <span class="pill ADDED">{len(added_items)} Added</span>
          <span class="pill DELETED">{len(deleted_items)} Deleted</span>
          <span class="pill UNCHANGED">{len(unchanged_items)} Unchanged</span>
        </div>
      </div>

      <div class="tablewrap">
        <table>
          <thead>
            <tr>
              <th>STATUS</th>
              <th>TYPE</th>
              <th>NAME OR PATH</th>
              <th>MONITORED ROOT</th>
              <th>DETAILS</th>
              <th>RISK LABEL</th>
            </tr>
          </thead>
          <tbody>
            {''.join(table_rows)}
          </tbody>
        </table>
      </div>

      <div class="buttons" style="margin-top:20px;">
        <a class="btn primary" href="/">← Return to Dashboard</a>
        <form method="post" action="/scan-all" style="margin:0">
          <button class="btn secondary" type="submit">🔄 Re-Scan Now</button>
        </form>
      </div>
    </section>
    """
    return page_template(content, "Scan Results | Sentinel")


# ==============================================================================
# 9. HTTP Web Server Request Handler
# ==============================================================================

class SentinelRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP GET and POST requests sent by your web browser."""

    def send_html(self, html_string, status_code=200):
        """Send an HTML page back to the browser."""
        data = html_string.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(data)

    def redirect_to(self, target_url):
        """Redirect browser to another URL (HTTP 303 See Other)."""
        self.send_response(303)
        self.send_header("Location", target_url)
        self.end_headers()

    def parse_form_data(self):
        """Read and parse form inputs sent via POST."""
        content_length = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_length).decode("utf-8")
        return parse_qs(post_body)

    # --------------------------------------------------------------------------
    # GET Requests
    # --------------------------------------------------------------------------
    def do_GET(self):
        try:
            # 1. Dashboard Homepage
            if self.path in ("/", "/index.html"):
                self.send_html(render_dashboard())
                return

            # 2. Dashboard with notification message
            if self.path.startswith("/?"):
                query = parse_qs(self.path.split("?", 1)[1])
                msg = query.get("msg", [""])[0]
                kind = query.get("kind", ["info"])[0]
                self.send_html(render_dashboard(msg, kind))
                return

            # 3. Open Native Windows Folder Picker Dialog
            if self.path == "/browse-folder":
                chosen_path = open_windows_folder_dialog()
                if chosen_path:
                    ok, msg = add_selected_folder(chosen_path)
                    kind = "success" if ok else "error"
                else:
                    msg = "No folder was selected (dialog was canceled)."
                    kind = "info"
                self.redirect_to(f"/?msg={quote(msg)}&kind={kind}")
                return

            # 404 Not Found
            self.send_html(page_template("<h2>Page Not Found</h2><a class='btn primary' href='/'>Return to Dashboard</a>"), 404)

        except Exception as error:
            self.send_html(page_template(f"<h2>Server Error</h2><p>{esc(error)}</p><a class='btn primary' href='/'>Return to Dashboard</a>"), 500)

    # --------------------------------------------------------------------------
    # POST Requests
    # --------------------------------------------------------------------------
    def do_POST(self):
        try:
            form = self.parse_form_data()

            # Action 1: Add folder path from text input
            if self.path == "/add-folder-path":
                path_text = form.get("folder_path", [""])[0]
                ok, msg = add_selected_folder(path_text)
                kind = "success" if ok else "error"
                self.redirect_to(f"/?msg={quote(msg)}&kind={kind}")
                return

            # Action 2: Add demo folder
            if self.path == "/add-demo-folder":
                ok, msg = add_selected_folder(str(DEMO_DIR))
                kind = "success" if ok else "info"
                self.redirect_to(f"/?msg={quote(msg)}&kind={kind}")
                return

            # Action 3: Remove folder from selection
            if self.path == "/remove-folder":
                folder_to_remove = form.get("folder", [""])[0]
                if folder_to_remove:
                    remove_selected_folder(folder_to_remove)
                self.redirect_to("/?msg=Folder%20removed%20from%20selection.&kind=info")
                return

            # Action 4: Clear all selected folders
            if self.path == "/clear-selection":
                clear_selected_folders()
                self.redirect_to("/?msg=Selection%20cleared.&kind=info")
                return

            # Action 5: Create Baseline for selected folders
            if self.path == "/create-baseline":
                selected_folders = load_selected_folders()
                if not selected_folders:
                    self.redirect_to("/?msg=Please%20select%20at%20least%20one%20folder%20first.&kind=error")
                    return

                new_baselines = []
                total_files = 0
                total_dirs = 0

                for folder_path in selected_folders:
                    scan_data = scan_folder(folder_path)
                    new_baselines.append({
                        "root_path": folder_path,
                        "files": scan_data["files"],
                        "directories": scan_data["directories"]
                    })
                    total_files += len(scan_data["files"])
                    total_dirs += len(scan_data["directories"])

                # Save to data/baseline.json
                save_baselines(new_baselines)

                # Clear selection queue after baseline is saved
                clear_selected_folders()

                msg = f"Baseline created successfully! Monitored {len(new_baselines)} root folder(s), {total_files} file(s), and {total_dirs} subfolder(s)."
                self.redirect_to(f"/?msg={quote(msg)}&kind=success")
                return

            # Action 6: Scan all monitored folders for changes
            if self.path == "/scan-all":
                baselines = load_baselines()
                if not baselines:
                    self.redirect_to("/?msg=No%20baseline%20found.%20Create%20a%20baseline%20first.&kind=error")
                    return

                reports = []
                for b in baselines:
                    root_path = b["root_path"]
                    saved_files = b.get("files", {})
                    saved_dirs = b.get("directories", [])
                    report = compare_folder_against_baseline(root_path, saved_files, saved_dirs)
                    reports.append(report)

                self.send_html(render_scan_results(reports))
                return

            # Action 7: Clear saved baselines
            if self.path == "/clear-baseline":
                save_baselines([])
                self.redirect_to("/?msg=All%20saved%20baselines%20have%20been%20deleted.&kind=info")
                return

            self.send_html(page_template("<h2>Page Not Found</h2><a class='btn primary' href='/'>Return to Dashboard</a>"), 404)

        except Exception as error:
            self.send_html(page_template(f"<h2>Server Error</h2><p>{esc(error)}</p><a class='btn primary' href='/'>Return to Dashboard</a>"), 500)

    def log_message(self, format_string, *args):
        """Clean log output to console without crashing Windows encodings."""
        print(f"[{self.address_string()}] {format_string % args}")


# ==============================================================================
# 10. Main Program Entrypoint
# ==============================================================================

if __name__ == "__main__":
    # Ensure demo and data directories exist
    DEMO_DIR.mkdir(exist_ok=True)
    DATA_DIR.mkdir(exist_ok=True)

    # Initialize sample demo files if they do not exist
    demo_file_1 = DEMO_DIR / "important_config.txt"
    if not demo_file_1.exists():
        demo_file_1.write_text("SENTINEL DEMO CONFIGURATION\nstatus=normal\n", encoding="utf-8")

    demo_file_2 = DEMO_DIR / "readme.txt"
    if not demo_file_2.exists():
        demo_file_2.write_text("This folder is used for testing Sentinel File Integrity Monitor.\n", encoding="utf-8")

    # Use standard single-threaded HTTPServer so Tkinter GUI calls run safely on the main thread
    server_address = (HOST, PORT)
    server = HTTPServer(server_address, SentinelRequestHandler)

    print("=" * 65)
    print(" [SENTINEL] FILE INTEGRITY MONITOR (Beginner-Friendly Edition)")
    print("=" * 65)
    print(f" -> Server running at: http://{HOST}:{PORT}")
    print(" -> Open the link above in your web browser (Chrome, Edge, etc.)")
    print(" -> Press Ctrl + C in this terminal to stop the server.")
    print("=" * 65)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
    finally:
        server.server_close()
        print("Server stopped cleanly. Goodbye!")
