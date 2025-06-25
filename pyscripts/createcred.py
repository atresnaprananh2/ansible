import base64
import getpass
import subprocess
from pytwist import * 
from pytwist.com.opsware.search import Filter
from pytwist.com.opsware.pkg import *

# Function to encode text using Base64
def encode_credentials(username, password):
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    return encoded_credentials

# Function to store the encoded credentials in a file
def store_credentials(encoded_credentials):
    with open("cred.b64", "w") as file:
        file.write(encoded_credentials)
    print("Encoded credentials have been stored in 'cred.b64'.")

# Get user input for the username and password
username = input("Please enter your username: ")
password = getpass.getpass("Please enter your password: ")

# Encode the credentials
encoded_credentials = encode_credentials(username, password)

# Store the encoded credentials in a file
store_credentials(encoded_credentials)

command = [
    "/opt/opsware/software_import/oupload",
    "--pkgtype", "Unknown",
    "--os", "UNIX",
    "--folder", "/Package Repository/All Red Hat Linux",
    "/opt/opsware/cred.b64"
]

# Run the command
try:
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    print("Command executed successfully!")
    ts = twistserver.TwistServer()
    pkgsvc = ts.pkg.UnknownPkgService
    filter2 = Filter()
    packages = pkgsvc.findUnknownPkgRefs(filter2)
    for package in packages2:
        if package.name == "cred.b64":
           print(package.name + " - " + str(package.id))
    print("Output:", result.stdout)

    
except subprocess.CalledProcessError as e:
    print("Error executing command:", e)
    print("Error Output:", e.stderr)