"""Create the separately mounted configuration encryption key."""
import argparse
import os
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
    print(f"Created {path}. This key decrypts the saved configuration.")
else:
    print(f"Preserved existing key: {path}")
print("Start the app and create the administrator password in the web interface.")
