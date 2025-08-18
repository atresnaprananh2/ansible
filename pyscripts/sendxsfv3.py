# FILE: run_scanner_and_unhide.py
# This script runs the scan, moves the file, and then makes it visible.
 
import os
import sys
import subprocess
import shutil
import time
import logging
import ctypes # Import ctypes to interact with Windows API
 
# --- CONFIGURATION (same as before) ---
BASE_DIRECTORY = r"C:\temp\ud_scanner"
XSF_SOURCE_DIR = r"C:\ProgramData\Micro Focus\Universal-Discovery"
RESULTS_DEST_DIR = os.path.join(BASE_DIRECTORY, "results")
 
def setup_logging():
    # ... (same as before) ...
    os.makedirs(BASE_DIRECTORY, exist_ok=True)
    log_file = os.path.join(BASE_DIRECTORY, "scan_only_log.log")
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        filename=log_file,
        filemode='w'
    )
 
def unhide_file(filepath):
    """Removes the 'Hidden' attribute from a file to make it visible."""
    try:
        # Windows API constant for the 'Hidden' attribute
        FILE_ATTRIBUTE_HIDDEN = 0x02
        attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
        if attrs != -1 and (attrs & FILE_ATTRIBUTE_HIDDEN):
            logging.info(f"File is hidden. Removing 'Hidden' attribute from: {os.path.basename(filepath)}")
            # Use a bitwise AND with the NOT of the attribute to remove it
            new_attrs = attrs & ~FILE_ATTRIBUTE_HIDDEN
            ctypes.windll.kernel32.SetFileAttributesW(filepath, new_attrs)
        else:
            logging.info("File is not hidden. No action needed.")
    except Exception as e:
        logging.warning(f"Could not unhide file '{filepath}'. Error: {e}")
 
def main():
    setup_logging()
    logging.info("--- Script started: Scan, Move, and Unhide ---")
    try:
        # ... (Scan and move logic is the same as before) ...
        os.chdir(BASE_DIRECTORY)
        server_name = os.environ.get('COMPUTERNAME', 'default-server-name')
        executable_path = os.path.join(BASE_DIRECTORY, "udscan.exe")
        command = [executable_path, "-cfg:scan.cxz", f"-l:{server_name}.xsf"]
        result = subprocess.run(command, check=False, text=True, capture_output=True)
        if result.returncode != 0:
            logging.error(f"udscan.exe failed with RC={result.returncode}. STDERR: {result.stderr}")
            sys.exit(1)
        logging.info("Scan completed successfully.")
        source_xsf_path = os.path.join(XSF_SOURCE_DIR, f"{server_name}.xsf")
        os.makedirs(RESULTS_DEST_DIR, exist_ok=True)
        destination_path = os.path.join(RESULTS_DEST_DIR, f"{server_name}.xsf")
        if os.path.exists(destination_path):
            os.remove(destination_path)
        shutil.move(source_xsf_path, destination_path)
        logging.info(f"File successfully moved to {destination_path}")
 
        # --- NEW STEP: Unhide the file ---
        unhide_file(destination_path)
 
    except Exception as e:
        logging.error("A critical error occurred.", exc_info=True)
        sys.exit(1)
    logging.info("--- Script finished successfully. ---")
    sys.exit(0)
 
if __name__ == "__main__":
    main()