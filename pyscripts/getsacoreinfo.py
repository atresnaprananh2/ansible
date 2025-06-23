from pytwist import twistserver

# Connect to SA
ts = twistserver.TwistServer()
server_service = ts.server.ServerService

# Replace with your target server's name
server_name = "Sol11"  # or use FQDN like "Sol11.mycompany.com"

# Retrieve the server object
server = server_service.getServerByName(server_name)

# Get the SA Core (slice) managing it
print(f"Server '{server.name}' is managed by SA Core Slice: {server.slice_name}")