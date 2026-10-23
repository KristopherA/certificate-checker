#!/bin/bash
# TEST-ONLY SSH host keys and known_hosts (0.9.0). SYNTHETIC: keys protect nothing; hosts are example.test.
set -euo pipefail
cd "$(dirname "$0")/Fixtures"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
g() { ssh-keygen -q -t "$1" ${3:+-b "$3"} -N '' -C "SYNTHETIC $2" -f "$T/$2" >/dev/null; cp "$T/$2.pub" "SYNTHETIC-ssh-$2.pub"; }
g ed25519 ed; g rsa rsa3072 3072; g rsa rsa1024 1024; g ed25519 ed-rotated
cat SYNTHETIC-ssh-ed.pub SYNTHETIC-ssh-rsa3072.pub > SYNTHETIC-ssh-host.pub
k() { cut -d' ' -f1,2 "SYNTHETIC-ssh-$1.pub"; }
{
  echo "# SYNTHETIC known_hosts"
  echo "ssh.example.test,10.0.0.1 $(k ed)"
  echo "[ssh.example.test]:2222 $(k rsa3072)"
  echo "*.wild.example.test $(k ed)"
  echo "@revoked ssh.example.test $(k rsa1024)"
} > "$T/kh"
cp "$T/kh" SYNTHETIC-ssh-known_hosts
# Hashed copy (ssh-keygen -H), as on systems with HashKnownHosts yes.
cp "$T/kh" "$T/khh"; ssh-keygen -H -f "$T/khh" >/dev/null 2>&1; cp "$T/khh" SYNTHETIC-ssh-known_hosts-hashed
