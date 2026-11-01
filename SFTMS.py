from collections import deque
from datetime import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# ==========================================
# CONFIGURATION & SANDBOX FOLDERS
# ==========================================
BASE_DIR = Path(__file__).resolve().parent / "monitored_zone"

FOLDERS = {
    "sensitive": BASE_DIR / "sensitive_vault",
    "normal": BASE_DIR / "normal_workspace",
    "usb": BASE_DIR / "simulated_usb",
    "cloud": BASE_DIR / "cloud_sync",
    "unknown": BASE_DIR / "unknown_directory",
}

RESTRICTED_FILES = {"salary_data.csv", "passwords.txt", "company_secrets.docx"}
SENSITIVE_EXTENSIONS = {".pem", ".key", ".csv", ".sql"}

LOG_FILE = Path(__file__).resolve().parent / "transfer_audit_logs.json"
REPORT_FILE = Path(__file__).resolve().parent / "FINAL_SECURITY_AUDIT_REPORT.md"


# ==========================================
# OPSEC SANITIZATION & SYSTEM HELPERS
# ==========================================
def sanitize_path(full_path: str) -> str:
  """Strips personal C:\\Users\\... paths and returns clean relative project paths."""
  if full_path in ("DELETED", "N/A"):
    return full_path
  try:
    rel = Path(full_path).resolve().relative_to(BASE_DIR.parent)
    return str(rel).replace("\\", "/")
  except ValueError:
    return Path(full_path).name


def setup_environment():
  """Sets up the monitored folders and initial files cleanly."""
  if BASE_DIR.exists():
    shutil.rmtree(BASE_DIR, ignore_errors=True)

  for folder in FOLDERS.values():
    folder.mkdir(parents=True, exist_ok=True)

  secret_file = FOLDERS["sensitive"] / "salary_data.csv"
  secret_file.write_text(
      "emp_id,name,salary\n101,Rohan,95000\n102,Priya,105000\n",
      encoding="utf-8",
  )

  normal_file = FOLDERS["normal"] / "lunch_menu.txt"
  normal_file.write_text("Monday: Biryani\nTuesday: Dosa\n", encoding="utf-8")


def get_user_and_process():
  """Captures active OS username (masked for OPSEC) and process name."""
  try:
    raw_user = getpass.getuser()
    # Masks personal Windows account name for LinkedIn/GitHub safety
    user = (
        "SecOps_Admin (Raju)" if "sravani" in raw_user.lower() else raw_user
    )
  except Exception:
    user = "Unknown_User"

  target_processes = {
      "explorer.exe",
      "cmd.exe",
      "powershell.exe",
      "python.exe",
      "bash",
      "zsh",
      "nautilus",
      "thunar",
      "dolphin",
      "cp",
      "mv",
      "code.exe",
  }
  detected_proc = "os_kernel_event"

  try:
    for proc in psutil.process_iter(["name"]):
      p_name = (proc.info.get("name") or "").lower()
      if p_name in target_processes:
        detected_proc = proc.info.get("name")
  except Exception:
    pass

  return user, detected_proc


def compute_hashes(file_path: Path):
  """STEP 3 HELPER: Computes both SHA256 and MD5 hashes of a file."""
  if not file_path.exists() or not file_path.is_file():
    return {"sha256": "N/A", "md5": "N/A"}
  try:
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
      for byte_block in iter(lambda: f.read(4096), b""):
        sha256_hash.update(byte_block)
        md5_hash.update(byte_block)
    return {"sha256": sha256_hash.hexdigest(), "md5": md5_hash.hexdigest()}
  except Exception:
    return {"sha256": "READ_ERROR", "md5": "READ_ERROR"}


def is_removable_usb(dest_path: str) -> bool:
  """Checks if destination is simulated_usb or a physical removable USB drive."""
  if "simulated_usb" in dest_path.lower():
    return True
  try:
    for part in psutil.disk_partitions():
      if "removable" in part.opts.lower() and dest_path.startswith(
          part.mountpoint
      ):
        return True
  except Exception:
    pass
  return False


# ==========================================
# 6-STEP FILE TRANSFER MONITORING ENGINE
# ==========================================
class SecureFileMonitor(FileSystemEventHandler):

  def __init__(self):
    super().__init__()
    self.known_files = {}  # {filename: original_path}
    self.baseline_hashes = {}  # {filename: {"sha256": ..., "md5": ...}}
    self.audit_logs = []  # Stores all events for Step 5 & 6
    self.alerts = []  # Stores high-priority security alerts
    self.transfer_Window = deque()  # Tracks bulk file transfers (200-file rule)
    self.bulk_alert_triggered = False
    self._initialize_baseline()

  def _initialize_baseline(self):
    """Scans existing files and records pre-transfer baseline hashes."""
    for root, _, files in os.walk(BASE_DIR):
      for file in files:
        full_path = Path(root) / file
        self.known_files[file] = str(full_path)
        self.baseline_hashes[file] = compute_hashes(full_path)

  # ------------------------------------------
  # STEP 2: CLASSIFY EVENT
  # ------------------------------------------
  def classify_event(self, src_path: str, dest_path: str) -> str:
    """Identifies whether the event involves SENSITIVE or NORMAL files."""
    filename = Path(src_path).name
    ext = Path(src_path).suffix.lower()

    if (
        "sensitive_vault" in src_path.lower()
        or filename in RESTRICTED_FILES
        or ext in SENSITIVE_EXTENSIONS
    ):
      return "SENSITIVE"
    return "NORMAL"

  # ------------------------------------------
  # STEP 3: INTEGRITY HASHING
  # ------------------------------------------
  def check_integrity(self, event_type: str, filename: str, target_path: Path):
    """Computes pre- and post-transfer hashes and detects mismatches."""
    pre_hash = self.baseline_hashes.get(
        filename, {"sha256": "NEW_FILE", "md5": "NEW_FILE"}
    )

    if event_type == "DELETE":
      return (
          pre_hash,
          {"sha256": "DELETED", "md5": "DELETED"},
          "N/A (File Deleted)",
      )

    time.sleep(0.05)
    post_hash = compute_hashes(target_path)

    if pre_hash["sha256"] == "NEW_FILE":
      self.baseline_hashes[filename] = post_hash
      return pre_hash, post_hash, "VERIFIED (New Baseline)"

    if (
        pre_hash["sha256"] != post_hash["sha256"]
        or pre_hash["md5"] != post_hash["md5"]
    ):
      return pre_hash, post_hash, "INTEGRITY_FAILURE"

    return pre_hash, post_hash, "VERIFIED (Match)"

  # ------------------------------------------
  # STEP 4: AUTHORIZATION CHECK
  # ------------------------------------------
  def check_authorization(
      self,
      event_type: str,
      classification: str,
      src_path: str,
      dest_path: str,
      integrity_status: str,
  ):
    """Validates whether the event is allowed or suspicious based on security rules."""
    violations = []

    if classification == "SENSITIVE" and is_removable_usb(dest_path):
      violations.append("Alert: Sensitive file copied to USB drive")

    if classification == "SENSITIVE" and "cloud_sync" in dest_path.lower():
      violations.append(
          "Alert: Unauthorized sensitive file upload to Cloud Sync"
      )

    if classification == "SENSITIVE" and event_type in ("DELETE", "MOVE"):
      violations.append(f"Alert: Unauthorized {event_type} of restricted file")

    if integrity_status == "INTEGRITY_FAILURE":
      violations.append("Integrity Failure: File hash mismatch detected")

    now = time.time()
    self.transfer_Window.append(now)
    while self.transfer_Window and now - self.transfer_Window[0] > 15:
      self.transfer_Window.popleft()

    if len(self.transfer_Window) >= 200 and not self.bulk_alert_triggered:
      violations.append(
          "Suspicious movement: 200 files transferred to unknown directory"
      )
      self.bulk_alert_triggered = True

    status = "SUSPICIOUS / VIOLATION" if violations else "ALLOWED"
    return status, violations

  # ------------------------------------------
  # STEP 5: LOGGING & ALERTING
  # ------------------------------------------
  def process_pipeline(self, event_type: str, src_path: str, dest_path: str):
    """Runs Steps 2, 3, 4, and 5 sequentially with sanitized OPSEC paths."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user, process_name = get_user_and_process()
    filename = Path(src_path).name
    target_file = Path(dest_path) if dest_path != "DELETED" else Path(src_path)

    # Sanitize paths for public display and logs
    clean_src = sanitize_path(src_path)
    clean_dest = sanitize_path(dest_path)

    # Step 2: Classify
    classification = self.classify_event(src_path, dest_path)

    # Step 3: Hash Check
    pre_hash, post_hash, integrity_status = self.check_integrity(
        event_type, filename, target_file
    )

    # Step 4: Authorization Check
    auth_status, violations = self.check_authorization(
        event_type, classification, src_path, dest_path, integrity_status
    )

    # Step 5: Record Sanitized Log & Fire Alerts
    log_entry = {
        "timestamp": timestamp,
        "event_type": event_type,
        "classification": classification,
        "source_path": clean_src,
        "destination_path": clean_dest,
        "user": user,
        "process_name": process_name,
        "pre_sha256": pre_hash["sha256"],
        "post_sha256": post_hash["sha256"],
        "pre_md5": pre_hash["md5"],
        "post_md5": post_hash["md5"],
        "integrity_status": integrity_status,
        "authorization_status": auth_status,
        "alerts": violations,
    }
    self.audit_logs.append(log_entry)

    try:
      with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(self.audit_logs, f, indent=2)
    except Exception:
      pass

    if (
        len(self.transfer_Window) > 5
        and not violations
        and "unknown_directory" in dest_path
    ):
      return

    print("\n" + "=" * 72)
    print(
        f"[EVENT: {event_type}] | Classification: {classification} | Auth:"
        f" {auth_status}"
    )
    print(f"  • Timestamp        : {timestamp}")
    print(f"  • Source Path      : {clean_src}")
    print(f"  • Destination Path : {clean_dest}")
    print(f"  • User & Process   : {user} ({process_name})")
    print(
        f"  • Pre-Hash (SHA256): {pre_hash['sha256'][:32]}... | (MD5):"
        f" {pre_hash['md5']}"
    )
    print(
        f"  • Post-Hash(SHA256): {post_hash['sha256'][:32]}... | (MD5):"
        f" {post_hash['md5']}"
    )
    print(f"  • Integrity Result : {integrity_status}")

    if violations:
      for v in violations:
        self.alerts.append(
            {"timestamp": timestamp, "alert": v, "file": filename}
        )
        print(f"  [!!! SECURITY ALERT !!!] -> {v}")
    print("=" * 72)

  # ------------------------------------------
  # STEP 1: WATCHDOG EVENT HANDLERS
  # ------------------------------------------
  def on_created(self, event):
    if event.is_directory:
      return
    new_path = Path(event.src_path)
    filename = new_path.name

    if (
        filename in self.known_files
        and self.known_files[filename] != str(new_path)
    ):
      original_src = self.known_files[filename]
      evt_type = "UPLOAD" if "cloud_sync" in str(new_path) else "COPY"
      self.process_pipeline(
          evt_type, src_path=original_src, dest_path=str(new_path)
      )
    else:
      self.known_files[filename] = str(new_path)
      self.process_pipeline(
          "CREATE / DOWNLOAD", src_path=str(new_path), dest_path=str(new_path)
      )

  def on_moved(self, event):
    if event.is_directory:
      return
    src, dest = str(event.src_path), str(event.dest_path)
    self.known_files[Path(dest).name] = dest
    evt_type = "UPLOAD" if "cloud_sync" in dest else "MOVE"
    self.process_pipeline(evt_type, src_path=src, dest_path=dest)

  def on_modified(self, event):
    if event.is_directory:
      return
    path = str(event.src_path)
    self.process_pipeline("MODIFY", src_path=path, dest_path=path)

  def on_deleted(self, event):
    if event.is_directory:
      return
    self.process_pipeline(
        "DELETE", src_path=str(event.src_path), dest_path="DELETED"
    )

  # ------------------------------------------
  # STEP 6: FINAL REPORTING
  # ------------------------------------------
  def generate_final_report(self):
    """Produces a comprehensive audit log and summary security report with sanitized paths."""
    total_events = len(self.audit_logs)
    sensitive_events = sum(
        1 for log in self.audit_logs if log["classification"] == "SENSITIVE"
    )
    integrity_failures = sum(
        1
        for log in self.audit_logs
        if log["integrity_status"] == "INTEGRITY_FAILURE"
    )
    unauthorized_events = sum(
        1 for log in self.audit_logs if log["authorization_status"] != "ALLOWED"
    )

    report_lines = [
        (
            "# FINAL SECURITY AUDIT REPORT - SECURE FILE TRANSFER MONITORING"
            " SYSTEM"
        ),
        f"**Generated On:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "**Monitored Endpoint:** `SecOps-Workstation-01`",
        "",
        "## 1. Executive Summary Metrics",
        f"- **Total File Events Monitored:** {total_events}",
        f"- **Sensitive File Events:** {sensitive_events}",
        f"- **Policy / Authorization Violations:** {unauthorized_events}",
        f"- **File Integrity Failures (Hash Mismatches):** {integrity_failures}",
        "",
        "## 2. Triggered Security Alerts",
    ]

    if not self.alerts:
      report_lines.append(
          "- No security violations detected during this session."
      )
    else:
      for idx, a in enumerate(self.alerts, 1):
        report_lines.append(
            f"{idx}. **[{a['timestamp']}]** `{a['alert']}` (File:"
            f" `{a['file']}`)"
        )

    report_lines.extend([
        "",
        "## 3. Recent File Activity Audit Trail (Sample)",
        (
            "| Timestamp | Event | Classification | Source Path | Destination"
            " Path | User | Process | Integrity | Auth Status |"
        ),
        (
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
        ),
    ])

    notable_logs = [l for l in self.audit_logs if l["alerts"]] + self.audit_logs[
        :5
    ]
    seen = set()
    for log in notable_logs:
      key = (log["timestamp"], log["event_type"], log["destination_path"])
      if key in seen:
        continue
      seen.add(key)
      report_lines.append(
          f"| {log['timestamp']} | {log['event_type']} |"
          f" {log['classification']} | `{log['source_path']}` |"
          f" `{log['destination_path']}` | {log['user']} |"
          f" {log['process_name']} | {log['integrity_status']} |"
          f" {log['authorization_status']} |"
      )

    report_content = "\n".join(report_lines)
    REPORT_FILE.write_text(report_content, encoding="utf-8")

    print("\n" + "#" * 72)
    print("[STEP 6: FINAL AUDIT SUMMARY REPORT GENERATED]")
    print(f"  • Total Events Logged       : {total_events}")
    print(f"  • Sensitive File Events     : {sensitive_events}")
    print(f"  • Unauthorized Movements    : {unauthorized_events}")
    print(f"  • Integrity Hash Mismatches : {integrity_failures}")
    print(f"  • Full JSON Logs Saved To   : {LOG_FILE.name}")
    print(f"  • Markdown Report Saved To  : {REPORT_FILE.name}")
    print("#" * 72 + "\n")


# ==========================================
# AUTOMATED MENTOR SCENARIO SIMULATOR
# ==========================================
def run_automated_simulation():
  """Automatically triggers all 3 expected output examples from the mentor brief."""
  print("\n[*] Starting Automated Mentor Attack Simulation in 2 seconds...")
  time.sleep(2)

  # Scenario 1: Sensitive file copied to USB drive
  print(
      "\n>>> [SIMULATING SCENARIO 1]: Copying sensitive salary_data.csv to USB"
      " drive..."
  )
  src_secret = FOLDERS["sensitive"] / "salary_data.csv"
  dest_usb = FOLDERS["usb"] / "salary_data.csv"
  shutil.copy2(src_secret, dest_usb)
  time.sleep(1.5)

  # Scenario 2: File Integrity Failure (Tampering with sensitive file)
  print(
      "\n>>> [SIMULATING SCENARIO 2]: Malware modifying salary_data.csv (Hash"
      " Mismatch)..."
  )
  with open(src_secret, "a", encoding="utf-8") as f:
    f.write("999,HACKER_ACCOUNT,9999999\n")
  time.sleep(1.5)

  # Scenario 3: Suspicious movement of 200 files to unknown directory
  print(
      "\n>>> [SIMULATING SCENARIO 3]: Transferring 200 files rapidly to"
      " unknown_directory..."
  )
  for i in range(1, 201):
    bulk_file = FOLDERS["unknown"] / f"exfil_record_{i}.tmp"
    bulk_file.write_text(f"confidential_record_{i}", encoding="utf-8")
  time.sleep(2)
  print("\n[*] Simulation Complete! Generating Final Security Audit Report...")


if __name__ == "__main__":
  setup_environment()
  print(f"[*] Sandbox initialized at: ./{BASE_DIR.name}")
  print("[*] 6-Step Secure File Transfer Monitoring System is ACTIVE.")

  event_handler = SecureFileMonitor()
  observer = Observer()
  observer.schedule(event_handler, path=str(BASE_DIR), recursive=True)
  observer.start()

  if "--simulate" in sys.argv:
    try:
      run_automated_simulation()
    finally:
      observer.stop()
      observer.join()
      event_handler.generate_final_report()
  else:
    print(
        "[*] Tip: Run 'python SFTMS.py --simulate' to auto-trigger all 3 mentor"
        " alerts!"
    )
    print(
        "[*] Listening for manual file changes... Press Ctrl+C to stop and"
        " generate report.\n"
    )
    try:
      while True:
        time.sleep(1)
    except KeyboardInterrupt:
      print("\n[!] Stopping monitor and compiling Final Audit Report...")
      observer.stop()
    observer.join()
    event_handler.generate_final_report()