import json
import jwt
import time
import sys
import argparse
import subprocess
from cryptography.hazmat.primitives import serialization
from pathlib import Path

# Read command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("algorithm", help="JWT signing algorithm")
parser.add_argument("private_key_location", help="Private key file location")
args = parser.parse_args()

# Read private key from the file
with open(args.private_key_location, "rb") as key_file:
    private_key = key_file.read().rstrip(b'\x00\n')

# Get the public key by executing the keypair show command
key_name = Path(args.private_key_location).name
cmd = f"keypair show {key_name}"
pub = subprocess.check_output(cmd, shell=True, text=True).strip()

exp = int(time.time() + 60)  # 1 minute from now

private_key = serialization.load_ssh_private_key(
    private_key, password=None)
payload = {"pub": pub, "exp": exp}
encoded = jwt.encode(payload, private_key, algorithm=args.algorithm)

# Create the output dictionary
output = {
    "kind": "ExecCredential",
    "apiVersion": "client.authentication.k8s.io/v1beta1",
    "spec": {"interactive": False},
    "status": {
        "expirationTimestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp)),
        "token": encoded
    }
}

# Output the JSON string
print(json.dumps(output))
