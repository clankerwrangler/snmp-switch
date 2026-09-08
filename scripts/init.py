"""Create the separately mounted encryption key and one-time setup token."""
import argparse
import os
import secrets
from pathlib import Path
from cryptography.fernet import Fernet

parser = argparse.ArgumentParser()
parser.add_argument("--key", default="secrets/config.key")
parser.add_argument("--docker", action="store_true", help="Allow container UID to read the key; protect the host directory")
args = parser.parse_args()
path = Path(args.key)
path.parent.mkdir(parents=True, exist_ok=True)
if args.docker:
    path.parent.chmod(0o700)
if not path.exists():
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(Fernet.generate_key())
    if args.docker:
        path.chmod(0o444)
    print(f"Created {path}. Keep this key outside the data volume and back it up securely.")
else:
    print(f"Preserved existing key: {path}")
print("Start the app. Its first-run console output contains the administrator setup token.")
