"""Offline (file-only) checks ported from the Mac app: S/MIME, DKIM, SSH host keys, WireGuard, IPsec, mTLS pairs.

Nothing here opens a network connection. Private keys are parsed in memory only to derive the public half."""
