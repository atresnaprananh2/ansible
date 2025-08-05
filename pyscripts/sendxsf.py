import os
import getpass
import subprocess

# Configuration
xsf_dir = r'C:\temp\ud_scanner\results'  # Windows directory with .xsf files
sa_core_ip = '172.17.40.33'              # SA Core IP
remote_dir = '/var/tmp'                  # Remote path on SA Core

# Prompt for SA Core credentials
sa_user = input("Enter SA Core username: ")
sa_pass = getpass.getpass("Enter SA Core password (will be prompted again by scp): ")

# Now you can use sa_user and sa_pass later in your code (e.g., for API/PyTwist login)
# print(sa_user)
# print(sa_pass)

# Loop through files and send via SCP
for filename in os.listdir(xsf_dir):
    if filename.lower().endswith('.xsf'):
        local_path = os.path.join(xsf_dir, filename)
        print(f"Uploading {filename}...")

        # Construct SCP command (using static SCP user = root)
        scp_cmd = [
            'scp',
            local_path,
            f'root@{sa_core_ip}:{remote_dir}'
        ]

        # Run the SCP command interactively (user will be prompted to input root password)
        subprocess.run(scp_cmd)