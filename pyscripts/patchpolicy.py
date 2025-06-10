from pytwist import twistserver
from pytwist.com.opsware.server import ServerRef
from pytwist.com.opsware.job import RepairPatchPolicyInput

# Configuration
USERNAME = "admin"
PASSWORD = "opsware_admin"
SERVER_NAME = "solarisips"
POLICY_NAME = "ipspolicy"
POLICY_FOLDER = "/Opsware/Tools/ipspolicy"

# Connect and authenticate
ts = twistserver.TwistServer()
ts.authenticate(USERNAME, PASSWORD)

# Get the server reference
server_service = ts.server.ServerService
servers = server_service.findServers(f"name CONTAINS \"{SERVER_NAME}\"")

if not servers:
    raise Exception(f"No server found with name {SERVER_NAME}")

server_ref = servers[0]
print(f"Found server: {server_ref}")

# Get the patch policy reference
folder_service = ts.folder.FolderService
patch_service = ts.patch.PatchPolicyService

folder = folder_service.getFolderByPath(POLICY_FOLDER)
policies = patch_service.getPatchPoliciesInFolder(folder)

policy_ref = next((p for p in policies if p.name == POLICY_NAME), None)

if not policy_ref:
    raise Exception(f"No patch policy named '{POLICY_NAME}' found in folder {POLICY_FOLDER}")

print(f"Found patch policy: {policy_ref}")

# Attach the policy to the server
patch_service.assignPatchPolicy(policy_ref, [server_ref])
print(f"Assigned policy '{POLICY_NAME}' to server '{SERVER_NAME}'")

# Start remediation job
job_service = ts.job.JobService
remediation_input = RepairPatchPolicyInput()
remediation_input.deviceRefs = [server_ref]
remediation_input.patchPolicyRef = policy_ref

job_ref = job_service.startRepairPatchPolicy(remediation_input)
print(f"Remediation job started: Job ID = {job_ref.id}")