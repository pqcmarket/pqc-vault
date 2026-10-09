#!/usr/bin/env bash
# Deploy pqc-vault.
#   ./deploy.sh devnet                    deployer from .env
#   ./deploy.sh devnet keys/some.json     deployer from a keyfile (throwaway devnet keys)
#   ./deploy.sh mainnet
#
# The program id comes from keys/pqc_vault-program-keypair.json and is identical
# on both clusters; it is also baked into the binary (declare_id!), so a different
# program keypair would need a rebuild. Re-running upgrades in place.
set -euo pipefail

cd "$(dirname "$0")"

CLUSTER="${1:-}"
KEYFILE="${2:-}"
if [[ "$CLUSTER" != "devnet" && "$CLUSTER" != "mainnet" ]]; then
  echo "usage: $0 <devnet|mainnet> [deployer-keypair.json]" >&2
  exit 1
fi

PROGRAM_KEYPAIR="keys/pqc_vault-program-keypair.json"
PROGRAM_SO="target/deploy/pqc_vault.so"

if [[ ! -f "$PROGRAM_KEYPAIR" ]]; then
  echo "error: $PROGRAM_KEYPAIR missing. The program id DNsPfPecrbnS7jFqMpEDG3VoWAdkuaU2VxsmaPENcg9F" >&2
  echo "       is baked into the binary; without its keypair you cannot deploy to that id." >&2
  exit 1
fi

echo "==> Building"
cargo build-sbf

echo "==> Testing (the program guards money; don't ship an untested build)"
cargo test --quiet 2>&1 | grep -E "test result" | grep -v " 0 passed"

DEPLOYER_KEYPAIR="$(mktemp)"
cleanup() { rm -f "$DEPLOYER_KEYPAIR"; }
trap cleanup EXIT INT TERM

if [[ -n "$KEYFILE" ]]; then
  cp "$KEYFILE" "$DEPLOYER_KEYPAIR"
  if [[ "$CLUSTER" == "devnet" ]]; then RPC_URL="https://api.devnet.solana.com"; else
    RPC_URL="$(python3 -c 'import sys;sys.path.insert(0,"scripts");import prepare_deploy as p,os;print(p.parse_env(".env").get("MAINNET_RPC_URL",""))')"
    [[ -n "$RPC_URL" ]] || { echo "error: MAINNET_RPC_URL is empty in .env" >&2; exit 1; }
  fi
else
  # Parses/validates .env, writes the keypair, echoes the cluster's RPC_URL back.
  RPC_URL="$(python3 scripts/prepare_deploy.py "$CLUSTER" "$DEPLOYER_KEYPAIR")"
fi

PROGRAM_ID="$(solana-keygen pubkey "$PROGRAM_KEYPAIR")"
DEPLOYER="$(solana-keygen pubkey "$DEPLOYER_KEYPAIR")"
BALANCE="$(solana balance "$DEPLOYER" --url "$RPC_URL")"

echo
echo "==> Cluster:    $CLUSTER"
echo "==> Program ID: $PROGRAM_ID"
echo "==> Deployer:   $DEPLOYER  (becomes the upgrade authority)"
echo "==> Balance:    $BALANCE"
echo "==> Size:       $(stat -c%s "$PROGRAM_SO") bytes"
echo

if solana account "$PROGRAM_ID" --url "$RPC_URL" >/dev/null 2>&1; then
  echo "==> This program already exists on $CLUSTER — the deploy will UPGRADE it."
  echo "    On mainnet that changes the rules for every live vault. Ctrl-C now if"
  echo "    that isn't what you want."
  echo
fi

solana program deploy \
  --url "$RPC_URL" \
  --keypair "$DEPLOYER_KEYPAIR" \
  --program-id "$PROGRAM_KEYPAIR" \
  --upgrade-authority "$DEPLOYER_KEYPAIR" \
  --max-sign-attempts 60 \
  "$PROGRAM_SO"

echo
echo "==> Deployed to $CLUSTER"
echo "    Program ID: $PROGRAM_ID"
if [[ "$CLUSTER" == "mainnet" ]]; then
  echo "    Explorer:   https://explorer.solana.com/address/$PROGRAM_ID"
  echo
  echo "    Upgrade authority is $DEPLOYER. To make the program immutable:"
  echo "      solana program set-upgrade-authority $PROGRAM_ID --final --url <rpc> --keypair <deployer>"
else
  echo "    Explorer:   https://explorer.solana.com/address/$PROGRAM_ID?cluster=devnet"
fi
echo
echo "If the deploy died partway, SOL may be stranded in a buffer account:"
echo "  solana program close --buffers --url \"<rpc>\" --keypair <your key>"
