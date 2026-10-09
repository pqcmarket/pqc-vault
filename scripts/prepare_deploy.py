#!/usr/bin/env python3
"""Read .env, validate it, and materialise the deployer keypair as a JSON file.

Prints the RPC URL for the requested cluster on stdout so deploy.sh can capture
it; everything else goes to stderr. .env is parsed here rather than shell-sourced
because RPC URLs routinely contain '?' and '&', which bash would interpret rather
than assign.

Usage: prepare_deploy.py <devnet|mainnet> <keypair-output-path>
"""

import json
import os
import sys

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_env(path):
    if not os.path.exists(path):
        die(f"{path} not found")
    env = {}
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            val = val.strip()
            # Strip one layer of matching quotes if the user added them.
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
                val = val[1:-1]
            env[key.strip()] = val
    return env


def b58decode(s):
    num = 0
    for ch in s:
        idx = B58_ALPHABET.find(ch)
        if idx == -1:
            die(f"invalid base58 character {ch!r} in DEPLOYER_PRIVATE_KEY")
        num = num * 58 + idx
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def to_secret_bytes(value):
    """Accept either a JSON byte array or a base58 string."""
    if value.lstrip().startswith("["):
        try:
            arr = json.loads(value)
        except json.JSONDecodeError as exc:
            die(f"DEPLOYER_PRIVATE_KEY looks like a JSON array but won't parse: {exc}")
        if not all(isinstance(b, int) and 0 <= b <= 255 for b in arr):
            die("DEPLOYER_PRIVATE_KEY array must contain only bytes (0-255)")
        return bytes(arr)
    return b58decode(value)


def main():
    if len(sys.argv) != 3:
        die("usage: prepare_deploy.py <devnet|mainnet> <keypair-output-path>")
    cluster, out_path = sys.argv[1], sys.argv[2]
    if cluster not in ("devnet", "mainnet"):
        die(f"unknown cluster {cluster!r}, expected 'devnet' or 'mainnet'")

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = parse_env(os.path.join(root, ".env"))

    rpc_key = "DEVNET_RPC_URL" if cluster == "devnet" else "MAINNET_RPC_URL"
    rpc = env.get(rpc_key, "")
    secret = env.get("DEPLOYER_PRIVATE_KEY", "")

    if not rpc:
        die(f"{rpc_key} is empty in .env — fill it in before deploying to {cluster}")
    if not secret:
        die("DEPLOYER_PRIVATE_KEY is empty in .env — fill it in before deploying")
    if "api.mainnet-beta.solana.com" in rpc:
        print(
            "warning: MAINNET_RPC_URL is the public endpoint. It rate-limits program\n"
            "         deploys and they usually fail partway. A private RPC is strongly\n"
            "         recommended. Continuing anyway.",
            file=sys.stderr,
        )

    raw = to_secret_bytes(secret)
    if len(raw) == 32:
        die(
            "DEPLOYER_PRIVATE_KEY is 32 bytes (seed only). Solana needs the full\n"
            "       64-byte secret key — export it from your wallet again, or use the\n"
            "       contents of a solana-keygen .json file."
        )
    if len(raw) != 64:
        die(f"DEPLOYER_PRIVATE_KEY decoded to {len(raw)} bytes, expected 64")

    # Create 0600 up front so the key is never briefly world-readable.
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(list(raw), fh)

    print(rpc)


if __name__ == "__main__":
    main()
