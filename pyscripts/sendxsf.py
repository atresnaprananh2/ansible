import os
import getpass
import subprocess
from pytwist.com.opsware.job import JobRef
import time
from pytwist import twistserver
from pytwist.com.opsware.script import ServerScriptJobArgs
from pytwist.com.opsware.server import ServerRef

# Configuration
xsf_dir = r'C:\temp\ud_scanner\results'  # Windows directory with .xsf files
sa_core_ip = '172.17.40.33'              # SA Core IP
remote_dir = '/var/tmp'                  # Remote path on SA Core
sa_core_id = 10001

# Prompt for SA Core credentials
sa_user = input("Enter SA Core username: ")
sa_pass = getpass.getpass("Enter SA Core password: ")

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



          # Authenticate to the TwistServer
ts = twistserver.TwistServer()
ts.authenticate(sa_user,sa_pass)

          # Set up script execution arguments
args = ServerScriptJobArgs()
args.targets = [ServerRef(sa_core_id)]

args.tailOutputSize = 10 * 1024  # Capture last 10 KB of output
args.timeOut = 7200    # Timeout after 2 hrs

userTag = "adHoc SHELL script upload to sacore"

          # PowerShell script to create and execute the Python script
source = '''
/opt/opsware/software_import/oupload --pkgtype "Unknown" --os "Windows*" --folder "/Package Repository/All Windows" /var/tmp/W2K22001.xsf
rm -f /var/tmp/W2K22001.xsf

'''

codeType = 'SH'  # Running a batch script that invokes PowerShell

          # Execute the script via OpenText Server Automation
jobRef = ts.script.ServerScriptService.startAdhocServerScript(source, codeType, args, userTag, None, None)

print(f"Created job {jobRef.getId()}, waiting for completion...")

          # Wait until the job completes
max_wait_time = 7200 
start_time = time.time()

while True:
    try:
        job_info = ts.job.JobService.getJobInfoVO(JobRef(jobRef.getId()))
                            
        if job_info is None:
            print(f"Failed to retrieve job info for {jobRef.getId()}. Exiting loop.")
            break

        # Check if the job has finished
        if job_info.status in [2, 3, 4, 6]:  # Completed, Failed, or Canceled
            print(f"Job {jobRef.getId()} finished with status: {job_info.status}")
            break

        print(f"Job {jobRef.getId()} is still running (status={job_info.status})...")
                            
    except Exception as e:
        print(f"Error retrieving job info: {e}")
        break

              # Timeout condition
    if time.time() - start_time > max_wait_time:
        print(f"Timeout reached while waiting for job {jobRef.getId()}. Exiting loop.")
        break

    time.sleep(10)  # Wait before checking again      