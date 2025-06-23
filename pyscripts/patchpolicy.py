from pytwist import * 

from pytwist.com.opsware.swmgmt import *
from pytwist.com.opsware.pkg import *
from pytwist.com.opsware.search import Filter
import json


ts = twistserver.TwistServer()
ts.authenticate("admin", "opsware_admin")

SoftwarePolicyService= ts.swmgmt.SoftwarePolicyService
PatchPolicyService= ts.swmgmt.PatchPolicyService
server_service = ts.server.ServerService
policy_name = "ipspolicy"

policylist = SoftwarePolicyService.findSoftwarePolicyRefs(Filter())
servers = server_service.findServerRefs(Filter())
packages = []

for pol in policylist:
    policy_vos = SoftwarePolicyService.getSoftwarePolicyVO(pol)
    if policy_vos.name == policy_name:
       print(policy_vos.name + "-" + str(policy_vos.ref.id))
       for srv in servers:
           server_vo = server_service.getServerVO(srv)
           if server_vo.primaryIP == "172.19.0.150":
              print(server_vo.mid)
              for i in range(len(policy_vos.installableItemData)):
                  package = {
                      "file_name": policy_vos.installableItemData[i].policyItem.name,
                      "object_id": policy_vos.installableItemData[i].policyItem.id
                  }
                  packages.append(package)
             
              break
       break
json_output = json.dumps(packages, indent=2)
print(json_output)


       
       
       







