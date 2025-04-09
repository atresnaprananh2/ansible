from pytwist.com.opsware.job import JobRef
import time
from pytwist import twistserver
from pytwist.com.opsware.script import ServerScriptJobArgs
from pytwist.com.opsware.server import ServerRef

# Authenticate to the TwistServer
ts = twistserver.TwistServer()
ts.authenticate("admin", "nh2123")

# Set up script execution arguments
args = ServerScriptJobArgs()
args.targets = [ServerRef(560001)]

args.tailOutputSize = 10 * 1024  # Capture last 10 KB of output
args.timeOut = 3600    # Timeout after 1 hr

userTag = "adHoc SHELL script"

# PowerShell script to create and execute the Python script
source = '''
# Step 1: Download the patch using embedded Python
cat > /tmp/otsadownload.py <<EOF
from coglib import downloader

downloader.Tsunami().fetch_unit(
    downloader.DownloadUnit(17060001, None, None, 'p36582781_190000_Linux-x86-64.zip', None, '/opt/opsware')
)
EOF

/opt/opsware/agent/bin/python3 /tmp/otsadownload.py
rm -f /tmp/otsadownload.py

# Step 2: Extract the patch
cd /opt/opsware
unzip -o p36582781_190000_Linux-x86-64.zip

# Step 3: Switch to oracle user and perform the patching sequence
su - oracle <<'EOORACLE'
# Stop listener
lsnrctl stop

# Shut down DB instance
sqlplus / as sysdba <<EOSQL
shutdown immediate;
exit;
EOSQL

# Apply the patch
cd /opt/opsware/36582781
$ORACLE_HOME/OPatch/opatch apply -silent



# Start DB instance
sqlplus / as sysdba <<EOSQL
startup;
exit;
EOSQL

# Start listener
lsnrctl start
EOORACLE

# Step 4: Clean up
rm -rf /opt/opsware/p36582781_190000_Linux-x86-64.zip
'''

codeType = 'SH'  # Running a batch script that invokes PowerShell

# Execute the script via OpenText Server Automation
jobRef = ts.script.ServerScriptService.startAdhocServerScript(source, codeType, args, userTag, None, None)

print(f"Created job {jobRef.getId()}, waiting for completion...")

# Wait until the job completes
max_wait_time = 3600 
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