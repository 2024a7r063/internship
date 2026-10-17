# 🛡️ Sentinel - File Integrity Monitor

A beginner-friendly, local Python cybersecurity tool that monitors files and folders on your computer using **SHA-256 cryptographic fingerprints**.

It detects if anyone **alters (edits)**, **adds**, or **deletes** files in your important directories.

---

## 🌟 Key Features
- **Live Integrity Monitoring on Dashboard:** Every time you load or refresh the page, Sentinel automatically scans your files and immediately flags altered files!
- **Accurate Alteration Detection:** If someone edits even a single word in a file (e.g. changing `"hii how are you"` to `"bye"`), Sentinel immediately detects that the SHA-256 fingerprint changed and highlights it in **RED (ALTERED / MODIFIED)**.
- **Easy Ways to Select Folders:**
  - **1-Click Common PC Folders:** Instantly select `📁 Downloads`, `📁 Desktop`, or `📁 Documents`.
  - **In-Browser Folder Explorer:** Click folders on your PC right inside the browser with a **`+ Select This Folder`** button next to each directory!
  - **Windows Dialog:** Opens the standard Windows folder picker window.
  - **Path Input:** Paste any folder path from your computer.
- **Built-in File Editor:** Click **`✏️ Edit / Test`** next to any file on the dashboard to test alterations directly in the web browser.
- **Pure Standard Python:** Uses only Python's built-in libraries (`hashlib`, `pathlib`, `http.server`, `tkinter`). No `pip install` required!
- **Beginner-Friendly Code (~450 lines):** Clean, readable, well-commented Python code written specifically for students and beginners learning Python.

---

## 🚀 How to Run on Windows

1. Open your terminal in this folder (`sentinel_file_integrity`).
2. Run the application:
   ```bash
   py app.py
   ```
   *(Or `python app.py` if python is registered in your PATH).*
3. Open your web browser and go to:
   ```
   http://127.0.0.1:5000
   ```
4. Keep the terminal open while using the app. Press `Ctrl + C` in the terminal when you want to stop.

---

## 🎯 How to Use It (Step-by-Step)

### Step 1: Select Folders from Your PC
- Use the **1-Click Buttons** (`Downloads`, `Desktop`, `Documents`, or `Demo Folder`).
- Or click **`🌐 In-Browser Folder Explorer`** and click **`+ Select This Folder`** next to any directory.
- Or click **`📂 Open Windows Explorer Dialog`**.
- Or paste any path into the box and click **`+ Add Path`**.

### Step 2: Create Baseline
- Click **`🚀 Create Baseline for Selected Folders`**.
- Sentinel calculates the unique SHA-256 fingerprint for every file and stores them in `data/baseline.json`.

### Step 3: Edit or Add Files & Check Status
- Open any monitored file in Notepad or VS Code, edit the text, and save (`Ctrl + S`).
- *Or simply click **`✏️ Edit / Test`** next to the file on the Sentinel web page to edit it right in the browser!*
- Open or refresh the Sentinel web page, or click **`🔄 Re-Check Integrity Now`**.
- Sentinel will immediately show:
  - 🔴 **ALTERED / MODIFIED:** Highlights changed files in red with old hash vs new hash.
  - 🟡 **NEW / ADDED:** Shows newly created files in amber.
  - 🔴 **DELETED:** Shows missing files.
  - 🟢 **UNCHANGED:** Shows files that match the baseline.
