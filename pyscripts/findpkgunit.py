import sys
from pytwist import *
from pytwist.com.opsware.search import Filter
from pytwist.com.opsware.pkg import ExecutableVO
from pytwist.com.opsware.pkg import InstallInfo


filter = Filter()
filter.expression = 'name = "cred.b64"'

# Create a TwistServer object.
ts = twistserver.TwistServer()

# Get a reference to ServerService.
packageService = ts.pkg.UnitService

# Perform the search, returning a tuple of references.
packages = packageService.findUnitRefs(filter)

if len(packages) < 1:
        print("No matching package found")
        sys.exit(3)


for package in packages:
    print(package.name + " - " + str(package.id))
	