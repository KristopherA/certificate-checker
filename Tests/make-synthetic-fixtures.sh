#!/bin/bash
# SYNTHETIC fixtures modelled on the public pfSense 2.7 config.xml schema and the WireGuard package layout.
# NOT real exports: every key and certificate is generated here, hostnames are *.example.test. Test data only.
set -euo pipefail
cd "$(dirname "$0")/Fixtures"
OPENSSL="$(brew --prefix openssl@3 2>/dev/null)/bin/openssl"; [ -x "$OPENSSL" ] || OPENSSL=openssl
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
O() { "$OPENSSL" "$@" 2>/dev/null; }
w() { base64 < "$1" | tr -d '\n' | fold -w 64; }   # wrapped base64 as some exports/editors leave it
ext() { printf '%s\n' "$@" > "$T/e"; echo "$T/e"; }
O req -x509 -newkey rsa:2048 -nodes -keyout "$T/root.key" -out "$T/root.crt" -days 3650 -sha256 -subj "/O=SYNTHETIC/CN=SYNTHETIC Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
issue() { # name subject issuer-crt issuer-key days ext...
  local n=$1 subj=$2 ic=$3 ik=$4 days=$5; shift 5
  O req -new -newkey rsa:2048 -nodes -keyout "$T/$n.key" -out "$T/$n.csr" -subj "$subj"
  O x509 -req -in "$T/$n.csr" -CA "$ic" -CAkey "$ik" -CAcreateserial -out "$T/$n.crt" -days "$days" -sha256 -extfile "$(ext "$@")"
}
issue int "/O=SYNTHETIC/CN=SYNTHETIC VPN Intermediate CA" "$T/root.crt" "$T/root.key" 3000 "basicConstraints=critical,CA:TRUE,pathlen:0" "keyUsage=critical,keyCertSign,cRLSign"
SRV=("basicConstraints=CA:FALSE" "keyUsage=critical,digitalSignature,keyEncipherment" "extendedKeyUsage=serverAuth,1.3.6.1.5.5.8.2.2")
issue ipsec "/CN=vpn.example.test" "$T/int.crt" "$T/int.key" 397 "${SRV[@]}" "subjectAltName=DNS:vpn.example.test,IP:203.0.113.10"
issue site "/CN=fw1.example.test" "$T/int.crt" "$T/int.key" 397 "${SRV[@]}" "subjectAltName=DNS:fw1.example.test"
issue ovpn "/CN=ovpn.example.test" "$T/int.crt" "$T/int.key" 397 "basicConstraints=CA:FALSE" "keyUsage=critical,digitalSignature,keyEncipherment" "extendedKeyUsage=serverAuth" "subjectAltName=DNS:ovpn.example.test"
O req -x509 -newkey rsa:2048 -nodes -keyout "$T/gui.key" -out "$T/gui.crt" -days 397 -sha256 -subj "/O=pfSense webConfigurator Self-Signed Certificate/CN=pfSense-SYNTHETIC" \
  -addext "basicConstraints=CA:FALSE" -addext "extendedKeyUsage=serverAuth" -addext "subjectAltName=DNS:fw.example.test"
cat > SYNTHETIC-pfsense-2.7-config.xml <<X
<?xml version="1.0"?>
<!-- SYNTHETIC test fixture. Modelled on the public pfSense 2.7 config.xml schema; NOT a real export. Generated keys, example.test names. -->
<pfsense>
	<version>23.3</version>
	<lastchange></lastchange>
	<system>
		<hostname>fw</hostname>
		<domain>example.test</domain>
		<webgui><protocol>https</protocol><ssl-certref>6500000000001</ssl-certref><port></port></webgui>
		<timezone>Etc/UTC</timezone>
	</system>
	<interfaces><wan><enable></enable><if>igc0</if><ipaddr>203.0.113.10</ipaddr><subnet>24</subnet></wan></interfaces>
	<openvpn>
		<openvpn-server><vpnid>1</vpnid><mode>server_tls_user</mode><protocol>UDP4</protocol><caref>6500000000a02</caref><certref>6500000000004</certref><description>SYNTHETIC remote access</description></openvpn-server>
	</openvpn>
	<ipsec>
		<client><enable></enable><user_source>Local Database</user_source><pool_address>203.0.113.0</pool_address><pool_netbits>24</pool_netbits></client>
		<phase1>
			<ikeid>1</ikeid><iketype>ikev2</iketype><interface>wan</interface><mobile></mobile><protocol>inet</protocol>
			<myid_type>fqdn</myid_type><myid_data>vpn.example.test</myid_data><peerid_type>any</peerid_type>
			<encryption><item><encryption-algorithm><name>aes</name><keylen>256</keylen></encryption-algorithm><hash-algorithm>sha256</hash-algorithm><dhgroup>14</dhgroup></item></encryption>
			<lifetime>28800</lifetime><authentication_method>eap-mschapv2</authentication_method>
			<certref>6500000000002</certref><caref>6500000000a02</caref><descr><![CDATA[SYNTHETIC mobile IKEv2]]></descr>
		</phase1>
		<phase1>
			<ikeid>2</ikeid><iketype>ikev2</iketype><interface>wan</interface><remote-gateway>198.51.100.20</remote-gateway><protocol>inet</protocol>
			<myid_type>fqdn</myid_type><myid_data>fw1.example.test</myid_data><peerid_type>fqdn</peerid_type><peerid_data>fw2.example.test</peerid_data>
			<authentication_method>cert</authentication_method><certref>6500000000003</certref><caref>6500000000a01</caref><descr><![CDATA[SYNTHETIC site-to-site]]></descr>
		</phase1>
		<phase1>
			<ikeid>3</ikeid><iketype>ikev2</iketype><disabled></disabled><authentication_method>cert</authentication_method><certref>6500000000004</certref><descr><![CDATA[SYNTHETIC disabled]]></descr>
		</phase1>
	</ipsec>
	<ca>
		<refid>6500000000a01</refid><descr><![CDATA[SYNTHETIC Root CA]]></descr><trust>disabled</trust><randomserial>enabled</randomserial>
		<crt>$(w "$T/root.crt")</crt>
		<prv>$(w "$T/root.key")</prv>
		<serial>3</serial>
	</ca>
	<ca>
		<refid>6500000000a02</refid><descr><![CDATA[SYNTHETIC VPN Intermediate CA]]></descr><trust>disabled</trust><caref>6500000000a01</caref>
		<crt>$(w "$T/int.crt")</crt>
		<prv>$(w "$T/int.key")</prv>
		<serial>4</serial>
	</ca>
	<cert><refid>6500000000001</refid><descr><![CDATA[webConfigurator default (SYNTHETIC)]]></descr><type>server</type>
		<crt>$(w "$T/gui.crt")</crt>
		<prv>$(w "$T/gui.key")</prv></cert>
	<cert><refid>6500000000002</refid><descr><![CDATA[SYNTHETIC IKEv2 server]]></descr><caref>6500000000a02</caref><type>server</type>
		<crt>$(w "$T/ipsec.crt")</crt>
		<prv>$(w "$T/ipsec.key")</prv></cert>
	<cert><refid>6500000000003</refid><descr><![CDATA[SYNTHETIC site-to-site]]></descr><caref>6500000000a02</caref><type>server</type>
		<crt>$(w "$T/site.crt")</crt>
		<prv>$(w "$T/site.key")</prv></cert>
	<cert><refid>6500000000004</refid><descr><![CDATA[SYNTHETIC OpenVPN server]]></descr><caref>6500000000a02</caref><type>server</type>
		<crt>$(w "$T/ovpn.crt")</crt>
		<prv>$(w "$T/ovpn.key")</prv></cert>
</pfsense>
X
# WireGuard package export (installedpackages/wireguard), X25519 keys from OpenSSL.
wgkey() { O genpkey -algorithm X25519 -out "$T/$1.pem"; O pkey -in "$T/$1.pem" -outform DER | tail -c 32 | base64 > "$T/$1.priv"; O pkey -in "$T/$1.pem" -pubout -outform DER | tail -c 32 | base64 > "$T/$1.pub"; }
for k in tun0 tun1 p1 p2 p3 p4; do wgkey $k; done
psk="$(head -c 32 /dev/urandom | base64)"
k() { cat "$T/$1.$2"; }
cat > SYNTHETIC-pfsense-wireguard-export.xml <<X
<?xml version="1.0"?>
<!-- SYNTHETIC test fixture. Modelled on the pfSense WireGuard package layout; NOT a real export. Generated keys, example.test names. -->
<pfsense>
	<installedpackages>
		<wireguard>
			<config><item><enable>on</enable><keep_conf>yes</keep_conf><resolve_interval>300</resolve_interval></item></config>
			<tunnels>
				<item><name>tun_wg0</name><enabled>yes</enabled><descr><![CDATA[SYNTHETIC road warriors]]></descr><listenport>51820</listenport>
					<privatekey>$(k tun0 priv)</privatekey><publickey>$(k tun0 pub)</publickey><mtu></mtu>
					<addresses><row><address>198.51.100.1</address><mask>24</mask><descr></descr></row></addresses></item>
				<item><name>tun_wg1</name><enabled>yes</enabled><descr><![CDATA[SYNTHETIC branch]]></descr><listenport>51821</listenport>
					<privatekey>$(k tun1 priv)</privatekey><publickey>$(k tun1 pub)</publickey>
					<addresses><row><address>203.0.113.1</address><mask>30</mask><descr></descr></row></addresses></item>
			</tunnels>
			<peers>
				<item><enabled>yes</enabled><tun>tun_wg0</tun><descr><![CDATA[SYNTHETIC laptop]]></descr><dynamic>yes</dynamic><persistentkeepalive></persistentkeepalive>
					<publickey>$(k p1 pub)</publickey><presharedkey>$psk</presharedkey>
					<allowedips><row><address>198.51.100.2</address><mask>32</mask><descr></descr></row></allowedips></item>
				<item><enabled>yes</enabled><tun>tun_wg0</tun><descr><![CDATA[SYNTHETIC phone]]></descr><dynamic>yes</dynamic>
					<publickey>$(k p2 pub)</publickey>
					<allowedips><row><address>198.51.100.3</address><mask>32</mask><descr></descr></row><row><address>2001:db8:66::3</address><mask>128</mask><descr></descr></row></allowedips></item>
				<item><enabled>yes</enabled><tun>tun_wg1</tun><descr><![CDATA[SYNTHETIC branch fw2]]></descr><endpoint>fw2.example.test</endpoint><port>51821</port><persistentkeepalive>25</persistentkeepalive>
					<publickey>$(k p3 pub)</publickey>
					<allowedips><row><address>203.0.113.2</address><mask>32</mask><descr></descr></row><row><address>203.0.113.128</address><mask>25</mask><descr></descr></row></allowedips></item>
				<item><enabled>no</enabled><tun>tun_wg0</tun><descr><![CDATA[SYNTHETIC retired]]></descr>
					<publickey>$(k p4 pub)</publickey><allowedips><row><address>198.51.100.9</address><mask>32</mask><descr></descr></row></allowedips></item>
			</peers>
		</wireguard>
	</installedpackages>
</pfsense>
X
echo "SYNTHETIC fixtures written."
