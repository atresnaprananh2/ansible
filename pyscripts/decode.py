import base64

# Read from the .b64 file
with open("cred.b64", "r") as file:
    encoded = file.read().strip()

# Decode Base64
decoded = base64.b64decode(encoded).decode('utf-8')

# Split into username and password
username, password = decoded.split(":", 1)  # The 1 ensures only the first ":" is used

print("Username:", username)
print("Password:", password)