#!/bin/bash
# TEST-ONLY WireGuard fixtures. These keys protect nothing; never use them on a real tunnel.
set -euo pipefail
OPENSSL="${OPENSSL:-$(brew --prefix openssl@3)/bin/openssl}"
D="$(cd "$(dirname "$0")" && pwd)/Fixtures"; mkdir -p "$D"; cd "$D"
pair() { local pem; pem="$("$OPENSSL" genpkey -algorithm x25519)"
  printf '%s\n' "$pem" | "$OPENSSL" pkey -outform DER | tail -c 32 | base64
  printf '%s\n' "$pem" | "$OPENSSL" pkey -pubout -outform DER | tail -c 32 | base64; }
read -r SPRIV SPUB < <(pair | paste -sd' ' -)
read -r CPRIV CPUB < <(pair | paste -sd' ' -)
read -r C2PRIV C2PUB < <(pair | paste -sd' ' -)
PSK="$("$OPENSSL" rand -base64 32)"
cat > wg-server.conf <<CONF
[Interface]
PrivateKey = $SPRIV
Address = 198.51.100.1/24
ListenPort = 51820

# Name = laptop
[Peer]
PublicKey = $CPUB
PresharedKey = $PSK
AllowedIPs = 198.51.100.2/32

# Name = phone
[Peer]
PublicKey = $C2PUB
AllowedIPs = 198.51.100.3/32, 2001:db8:66::3/128
CONF
cat > wg-client.conf <<CONF
[Interface]
PrivateKey = $CPRIV
Address = 198.51.100.2/32

[Peer]
PublicKey = $SPUB
PresharedKey = $PSK
AllowedIPs = 198.51.100.0/24, 203.0.113.0/24
Endpoint = vpn.example.internal:51820
PersistentKeepalive = 25
CONF
cat > wg-bad.conf <<CONF
[Interface]
PrivateKey = $SPRIV
Address = 198.51.100.1/24

[Peer]
PublicKey = $CPUB
PresharedKey = not-a-key
AllowedIPs = 198.51.100.0/24
Endpoint = fe80::1:51820

[Peer]
PublicKey = $CPUB
AllowedIPs = 198.51.100.0/24, 300.1.1.1/32
Endpoint = vpn.example.internal

[Peer]
PublicKey = $SPUB
AllowedIPs = 198.51.100.5/32
CONF
cat > pfsense-config.xml <<CONF
<?xml version="1.0"?>
<pfsense><installedpackages><wireguard>
<tunnels><item><name>tun_wg0</name><enabled>yes</enabled><listenport>51820</listenport>
<privatekey>$SPRIV</privatekey><publickey>$C2PUB</publickey>
<addresses><row><address>198.51.100.1</address><mask>24</mask></row></addresses></item></tunnels>
<peers><item><enabled>yes</enabled><tun>tun_wg0</tun><descr>laptop</descr><publickey>$CPUB</publickey><presharedkey>$PSK</presharedkey>
<allowedips><row><address>198.51.100.2</address><mask>32</mask></row></allowedips></item>
<item><enabled>yes</enabled><tun>tun_wg0</tun><descr>branch</descr><publickey>$C2PUB</publickey><endpoint>branch.example.internal</endpoint><port>51820</port>
<allowedips><row><address>198.51.100.0</address><mask>24</mask></row></allowedips></item></peers>
</wireguard></installedpackages></pfsense>
CONF
chmod 600 wg-*.conf pfsense-config.xml
echo "WireGuard fixtures written to $D"
