import os
import getpass
import time
import base64
import hashlib
from pytwist import twistserver
from pytwist.com.opsware.job import JobRef
from pytwist.com.opsware.script import ServerScriptJobArgs
from pytwist.com.opsware.server import ServerRef

# --- Configuration ---
xsf_dir = r'C:\temp\ud_scanner\results'
remote_dir = '/var/tmp'
sa_core_id = 10001

# --- Credentials & Authentication ---
sa_user = input("Enter SA Core username: ")
sa_pass = getpass.getpass("Enter SA Core password: ")

try:
    ts = twistserver.TwistServer()
    ts.authenticate(sa_user, sa_pass)
    print("Successfully authenticated to the SA Core.")
except Exception as e:
    print(f"Failed to authenticate. Aborting. Error: {e}")
    exit()

# --- Main loop to process each file ---
for filename in os.listdir(xsf_dir):
    if not filename.lower().endswith('.xsf'):
        continue

    print("=" * 60)
    print(f"Starting process for file: {filename}")
    
    local_path = os.path.join(xsf_dir, filename)
    remote_path = f"{remote_dir}/{filename}"
    
    # ==============================================================================
    #   STEP 1: TRANSFER THE FILE
    #   (Checksum verification has been REMOVED as requested)
    # ==============================================================================
    
    transfer_successful = False
    try:
        print(f"\n--- STEP 1: Transferring '{filename}' ---")
        
        with open(local_path, 'rb') as f:
            file_content = f.read()
        encoded_content = base64.b64encode(file_content).decode('ascii')

        # This script just creates the file. No checksum output.
        transfer_source = f"echo '{encoded_content}' | base64 --decode > {remote_path}"
        
        args = ServerScriptJobArgs()
        args.targets = [ServerRef(sa_core_id)]
        args.timeOut = 7200
        
        jobRef = ts.script.ServerScriptService.startAdhocServerScript(transfer_source, 'SH', args, f"Transfer file: {filename}", None, None)
        
        # ======================================================================
        #   USING YOUR WAITING LOOP EXACTLY AS PROVIDED. NO CHANGES.
        # ======================================================================
        print(f"Created job {jobRef.getId()}, waiting for completion...")
        max_wait_time = 7200 
        start_time = time.time()
        job_info = None

        while True:
            try:
                job_info = ts.job.JobService.getJobInfoVO(JobRef(jobRef.getId()))
                if job_info is None:
                    print(f"Failed to retrieve job info for {jobRef.getId()}. Exiting loop.")
                    break
                if job_info.status in [2, 3, 4, 6]:
                    print(f"Job {jobRef.getId()} finished with status: {job_info.status}")
                    break
                print(f"Job {jobRef.getId()} is still running (status={job_info.status})...")
            except Exception as e:
                print(f"Error retrieving job info: {e}")
                break
            if time.time() - start_time > max_wait_time:
                print(f"Timeout reached while waiting for job {jobRef.getId()}. Exiting loop.")
                job_info = None
                break
            time.sleep(10)
        # ======================================================================
        #   END OF YOUR WAITING LOOP
        # ======================================================================

        # Check the result of the loop. If status is 6, it's a success.
        if job_info and job_info.status == 6:
            print("SUCCESS: Transfer job finished with status 6. Proceeding to Step 2.")
            transfer_successful = True
        else:
            status = job_info.status if job_info else "Timed Out or Failed"
            raise Exception(f"Job FAILED. Expected status 6 but loop finished with status {status}.")

    except Exception as e:
        print(f"CRITICAL ERROR in STEP 1 (Transfer): {e}")
        print("Skipping this file.")
        continue

    # ==============================================================================
    #   STEP 2: PROCESS THE FILE (IF STEP 1 SUCCEEDED)
    # ==============================================================================

    if transfer_successful:
        try:
            print(f"\n--- STEP 2: Processing '{filename}' on the SA Core ---")
            
            process_source = f"""
/opt/opsware/software_import/oupload --pkgtype "Unknown" --os "Windows*" --folder "/Package Repository/All Windows" {remote_path}
rm -f {remote_path}
"""
            args = ServerScriptJobArgs()
            args.targets = [ServerRef(sa_core_id)]
            args.timeOut = 7200
            
            jobRef = ts.script.ServerScriptService.startAdhocServerScript(process_source, 'SH', args, f"Process file: {filename}", None, None)
            
            # Using your waiting loop again for the second job.
            print(f"Created job {jobRef.getId()}, waiting for completion...")
            max_wait_time = 7200 
            start_time = time.time()
            job_info = None

            while True:
                try:
                    job_info = ts.job.JobService.getJobInfoVO(JobRef(jobRef.getId()))
                    if job_info is None: break
                    if job_info.status in [2, 3, 4, 6]: break
                except Exception as e: break
                if time.time() - start_time > max_wait_time: job_info = None; break
                time.sleep(10)

            if job_info and job_info.status == 6:
                print(f"SUCCESS: File '{filename}' has been processed and cleaned up.")
            else:
                status = job_info.status if job_info else "Timed Out or Failed"
                raise Exception(f"Processing Job FAILED. Expected status 6 but got {status}.")

        except Exception as e:
            print(f"CRITICAL ERROR in STEP 2 (Processing): {e}")
            continue
        
print("=" * 60)
print("All files processed.")