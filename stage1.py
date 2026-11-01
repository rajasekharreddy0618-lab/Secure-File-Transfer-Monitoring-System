from datetime import datetime
import getpass
import os
from pathlib import Path
import time
import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# ==========================================
# 1. CROSS-PLATFORM SANDBOX SETUP
# ==========================================
BASE_DIR = Path(__file__).resolve().parent / "monitored_zone"

FOLDERS = {
    "sensitive": BASE_DIR / "sensitive_vault",
    "normal": BASE_DIR / "normal_workspace",
    "usb": BASE_DIR / "simulated_usb",
    "cloud": BASE_DIR / "cloud_sync",
}


def setup_environment():
  """Creates the test folders and dummy files automatically."""
  for folder in FOLDERS.values():
    folder.mkdir(parents=True, exist_ok=True)

  # Create a dummy sensitive file and normal file for testing
  secret_file = FOLDERS["sensitive"] / "salary_data.csv"
  if not secret_file.exists():
    secret_file.write_text("emp_id,name,salary\n101,Rohan,95000\n")

  normal_file = FOLDERS["normal"] / "lunch_menu.txt"
  if not normal_file.exists():
    normal_file.write_text("Monday: Biryani\nTuesday: Dosa\n")


# ==========================================
# 2. USER & PROCESS ATTRIBUTION HELPER
# ==========================================
def get_user_and_process():
  """Grabs the active OS username and the most likely active file/shell process."""
  try:
    user = getpass.getuser()
  except Exception:
    user = "Unknown_User"

  # Scan common processes that interact with files across Windows & Linux
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
    # Check recently active processes owned by the current user
    for proc in psutil.process_iter(["name", "username"]):
      p_name = (proc.info.get("name") or "").lower()
      if p_name in target_processes:
        detected_proc = proc.info.get("name")
  except Exception:
    pass

  return user, detected_proc


# ==========================================
# 3. STEP 1: FILE SYSTEM MONITOR (CCTV)
# ==========================================
class FileTransferMonitor(FileSystemEventHandler):

  def __init__(self):
    super().__init__()
    # Memory of known files to help distinguish COPY from newly created files
    self.known_files = {}
    self._scan_existing_files()

  def _scan_existing_files(self):
    """Records initial files and their paths before monitoring starts."""
    for root, _, files in os.walk(BASE_DIR):
      for file in files:
        full_path = Path(root) / file
        self.known_files[file] = str(full_path)

  def _log_event(self, event_type: str, src_path: str, dest_path: str = "N/A"):
    """Formats and prints the 5 mandatory mentor requirements."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user, process_name = get_user_and_process()

    print("\n" + "=" * 60)
    print(f"[STEP 1: EVENT DETECTED] -> {event_type}")
    print(f"  • Timestamp        : {timestamp}")
    print(f"  • Source Path      : {src_path}")
    print(f"  • Destination Path : {dest_path}")
    print(f"  • User             : {user}")
    print(f"  • Process Name     : {process_name}")
    print("=" * 60)

  def on_created(self, event):
    if event.is_directory:
      return

    new_path = Path(event.src_path)
    filename = new_path.name

    # Check if this filename already exists in our known files (Indicates a COPY)
    if (
        filename in self.known_files
        and self.known_files[filename] != str(new_path)
    ):
      original_source = self.known_files[filename]

      # Check if destination is the cloud folder -> classify as UPLOAD
      if "cloud_sync" in str(new_path):
        event_type = "UPLOAD (Copy to Cloud)"
      else:
        event_type = "COPY"

      self._log_event(
          event_type=event_type,
          src_path=original_source,
          dest_path=str(new_path),
      )
    else:
      self.known_files[filename] = str(new_path)
      self._log_event(
          event_type="CREATE / DOWNLOAD",
          src_path=str(new_path),
          dest_path=str(new_path),
      )

  def on_Moved(self, event):
    # Watchdog uses on_moved (lowercase)
    pass

  def on_moved(self, event):
    if event.is_directory:
      return
    src = Path(event.src_path)
    dest = Path(event.dest_path)
    self.known_files[dest.name] = str(dest)

    event_type = "UPLOAD (Move to Cloud)" if "cloud_sync" in str(dest) else "MOVE"
    self._log_event(event_type=event_type, src_path=str(src), dest_path=str(dest))

  def on_modified(self, event):
    if event.is_directory:
      return
    self._log_event(
        event_type="MODIFY",
        src_path= str(event.src_path),
        dest_path=str(event.src_path),
    )

  def on_deleted(self, event):
    if event.is_directory:
      return
    deleted_path = Path(event.src_path)
    self._log_event(
        event_type="DELETE",
        src_path=str(deleted_path),
        dest_path="DELETED",
    )


if __name__ == "__main__":
  setup_environment()
  print(f"[*] Sandbox initialized at: {BASE_DIR}")
  print("[*] Starting Step 1: File System Monitor...")
  print("[*] Try copying 'salary_data.csv' from 'sensitive_vault' to 'simulated_usb'!")
  print("[*] Press Ctrl+C to stop.\n")

  event_handler = FileTransferMonitor()
  observer = Observer()
  observer.schedule(event_handler, path=str(BASE_DIR), recursive=True)
  observer.start()

  try:
    while True:
      time.sleep(1)
  except KeyboardInterrupt:
    print("\n[!] Stopping monitor...")
    observer.stop()
  observer.join()