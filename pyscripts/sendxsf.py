import os
import getpass
import subprocess

# Configuration
xsf_dir = r'C:\temp\ud_scanner\results'  # Windows directory with .xsf files
sa_core_ip = '172.17.40.33'              # SA Core IP
remote_dir = '/var/tmp'                  # Remote path on SA Core

# Prompt for SA Core credentials
username = input("Enter SA Core username: ")
_ = getpass.getpass("Enter SA Core password (will be prompted again by scp): ")  # Just a pause so user sees both prompts

# Loop through files and send via SCP
for filename in os.listdir(xsf_dir):
    if filename.lower().endswith('.xsf'):
        local_path = os.path.join(xsf_dir, filename)
        print(f"Uploading {filename}...")

        # Construct SCP command (no sshpass)
        scp_cmd = [
            'scp',
            local_path,
            f'root@{sa_core_ip}:{remote_dir}'
            
        ]

        # Run the command interactively
        subprocess.run(scp_cmd)