"""Fix guidance per finding topic and platform, ported from Source/Sources/Core/Guidance.swift (Advisor).

Display and copy only: nothing here is ever executed (this module imports no subprocess or os helpers, and
tests/test_app.py checks that). Host names are shell-quoted so a pasted command cannot be hijacked by a
hostile certificate or input. Differences from the Mac: commands use the server's own `openssl` (no Homebrew
path), the Mac's KB links are not shown, and the per-service advisors (Remote/Appliance/Stack/Vendor bindings)
fall back to the generic "Reissue and redeploy" steps (shared/known-differences.yaml).
"""

from __future__ import annotations

import enum
import shlex
from dataclasses import dataclass, field

from .model import Finding, Topic
from .probe import Target, openssl_command
from .services import Service

OPENSSL = "openssl"


class Platform(enum.StrEnum):
    """Same raw values as Platform in Source/Sources/Core/Targets.swift."""

    GENERIC = "Generic / unknown"
    PFSENSE = "pfSense"
    WINDOWS_AD = "Windows AD (LDAPS)"
    WINDOWS_IIS = "Windows IIS / RD Gateway"
    NGINX = "Linux nginx"
    APACHE = "Linux Apache"
    ZIMBRA = "Zimbra mail"
    MYSQL = "MySQL"
    SYNOLOGY = "Synology DSM"
    PROXMOX_VE = "Proxmox VE"
    PROXMOX_BACKUP = "Proxmox Backup Server"
    MACOS = "macOS"
    WINDOWS_RDP = "Windows RDP host"
    WINDOWS_RD_GATEWAY = "Windows RD Gateway"
    WINDOWS_WINRM = "Windows WinRM"
    DOCKER_REGISTRY = "Docker registry"
    ELASTIC_STACK = "Elastic Stack (Beats / Logstash / Elasticsearch)"
    MUNKI = "Munki"
    FILEMAKER = "FileMaker Server"
    RETROSPECT = "Retrospect"
    HP_PRINTER = "HP printer (EWS)"
    BARRACUDA = "Barracuda WAF"


_SERVICE_PLATFORM = {
    Service.SYNOLOGY_DSM: Platform.SYNOLOGY,
    Service.PROXMOX_VE: Platform.PROXMOX_VE,
    Service.PROXMOX_BACKUP: Platform.PROXMOX_BACKUP,
    Service.DOCKER_REGISTRY: Platform.DOCKER_REGISTRY,
    Service.LOGSTASH_BEATS: Platform.ELASTIC_STACK,
    Service.ELASTICSEARCH: Platform.ELASTIC_STACK,
    Service.MUNKI_REPO: Platform.MUNKI,
    Service.FILEMAKER: Platform.FILEMAKER,
    Service.RETROSPECT_CONSOLE: Platform.RETROSPECT,
    Service.HP_PRINTER: Platform.HP_PRINTER,
    Service.BARRACUDA_SERVICE: Platform.BARRACUDA,
    Service.BARRACUDA_MANAGEMENT: Platform.BARRACUDA,
    Service.RDP: Platform.WINDOWS_RDP,
    Service.RD_GATEWAY: Platform.WINDOWS_RD_GATEWAY,
    Service.WINRM_HTTPS: Platform.WINDOWS_WINRM,
}


@dataclass(frozen=True)
class Guidance:
    title: str
    steps: list[str]
    commands: list[str] = field(default_factory=list)  # copy-only text, never executed


def default_platform(s: Service) -> Platform | None:
    return _SERVICE_PLATFORM.get(s)


def for_findings(findings: list[Finding], platform: Platform, target: Target | None = None) -> list[Guidance]:
    """Guidance for every topic with a warning or failure, in finding order, de-duplicated by title."""
    out: dict[str, Guidance] = {}
    for f in findings:
        if f.severity.label not in ("warning", "fail"):
            continue
        for g in guidance(f.topic, platform, target):
            out.setdefault(g.title, g)
    return list(out.values())


def guidance(topic: Topic, platform: Platform, target: Target | None = None) -> list[Guidance]:
    if platform == Platform.GENERIC and target is not None:
        platform = default_platform(target.service) or platform
    host = target.expected_name if target else "HOST"
    qh = shlex.quote(host)
    out: list[Guidance] = []
    if topic in (Topic.EXPIRY, Topic.WEAK_KEY, Topic.WEAK_SIGNATURE, Topic.EKU, Topic.NO_SAN, Topic.HOSTNAME,
                 Topic.CA_LEAF, Topic.LONG_VALIDITY):  # fmt: skip
        out.append(replace(platform, host, topic))
    elif topic in (Topic.CHAIN_ORDER, Topic.CHAIN_INCOMPLETE):
        out.append(Guidance("Serve the full chain in order", [
            "Build the bundle as leaf first, then each intermediate. Do not include the root unless the platform "
            "requires it.",
            "Download the matching intermediate from the issuing CA (AD CS: certsrv or the CA's AIA path; pfSense: "
            "System › Cert Manager › CAs › Export).",
            "Re-import the bundle on the service, then re-check here.",
        ], ["cat leaf.crt intermediate.crt > fullchain.pem",
            f"{OPENSSL} crl2pkcs7 -nocrl -certfile fullchain.pem | {OPENSSL} pkcs7 -print_certs -noout"]))  # fmt: skip
        out.append(replace(platform, host, topic))
    elif topic == Topic.TRUST:
        out.append(Guidance("Establish trust in the issuing CA", [
            "Identify the root CA in the chain. For AD CS or a pfSense internal CA, the root must be distributed to "
            "clients (GPO for Windows, configuration profile for macOS).",
            "Do not add trust for a leaf certificate. Distribute the CA through the normal managed process.",
            "If the server omitted an intermediate, fix the server chain instead (see chain guidance).",
        ], [f"security verify-cert -c leaf.pem -p ssl -s {qh}",
            f"{OPENSSL} verify -CAfile root.pem -untrusted intermediate.pem leaf.pem"]))  # fmt: skip
        if platform == Platform.PROXMOX_BACKUP:
            out.append(PBS_FINGERPRINT)
    elif topic == Topic.KEY_MISMATCH:
        out.append(Guidance("Pair the certificate with its private key", [
            "The certificate was issued for a different key. Locate the key generated with the CSR, or create a new "
            "CSR and reissue.",
            "Run the comparison on an approved admin workstation. Both hashes must be identical.",
            "Never email or ticket private keys.",
        ], [f"{OPENSSL} x509 -in cert.pem -noout -pubkey | {OPENSSL} pkey -pubin -outform pem | {OPENSSL} sha256",
            f"{OPENSSL} pkey -in key.pem -pubout -outform pem | {OPENSSL} sha256"]))  # fmt: skip
    elif topic == Topic.START_TLS:
        out.append(Guidance("Enable TLS on the service", starttls_steps(target.service if target else None, platform),
                            [openssl_command(target)] if target else []))  # fmt: skip
    elif topic == Topic.CONNECTION:
        out.append(Guidance("Check reachability first", [
            "Confirm the host name resolves and the port is open from this network (VPN state matters for internal "
            "services).",
            "Compare the resolved IP shown in the result with the address you expect (split DNS).",
            "Check the firewall rule on pfSense (Firewall › Rules) for the source network.",
        ], [f"nc -vz {shlex.quote(target.host if target else 'HOST')} {target.port if target else 443}",
            openssl_command(target) if target else f"{OPENSSL} s_client -connect HOST:443 </dev/null"]))  # fmt: skip
    return out


PBS_FINGERPRINT = Guidance("Proxmox Backup Server: keep the self-signed fingerprint pinned", [
    "PBS uses its own self-signed certificate by default; PVE trusts it through the fingerprint stored with the "
    "storage entry, not the system trust store.",
    "Read the current fingerprint on the PBS host, then compare it to the PVE storage configuration (Datacenter › "
    "Storage › the PBS entry).",
    "If PBS regenerated its certificate, update the fingerprint in PVE.",
], ["proxmox-backup-manager cert info | grep -i fingerprint", "grep -A8 'pbs:' /etc/pve/storage.cfg",
    "pvesm set STORAGE_ID --fingerprint 'AA:BB:…'"])  # fmt: skip


def starttls_steps(s: Service | None, p: Platform) -> list[str]:
    if s == Service.LDAP_STARTTLS:
        return [
            "StartTLS on 389 needs a valid Server Authentication certificate in the DC's Local Computer › Personal "
            "store, the same one LDAPS on 636 uses.",
            "Confirm the certificate includes the DC FQDN and the domain name in the SAN.",
            "After installing, the DC picks it up without reboot; force it with the renewServerCertificate LDIF.",
        ]
    if s == Service.MYSQL:
        return [
            "Set ssl_ca, ssl_cert and ssl_key in my.cnf (MySQL 8 enables TLS automatically when files are present).",
            "Reload with ALTER INSTANCE RELOAD TLS (MySQL 8.0.16+) or restart the service.",
            "Confirm with SHOW VARIABLES LIKE 'have_ssl'.",
        ]
    if s in (Service.SMTP_STARTTLS, Service.IMAP_STARTTLS, Service.POP3_STARTTLS):
        if p == Platform.ZIMBRA:
            return [
                "Check zimbraMtaTlsSecurityLevel and that a commercial or self-signed certificate is deployed with "
                "zmcertmgr.",
                "Restart the MTA/mailbox services after deploying.",
            ]
        return [
            "Enable STARTTLS on the mail service and configure the certificate and key paths.",
            "Some ports (465, 993, 995) use implicit TLS instead; choose the matching service type.",
        ]
    if s == Service.RDP:
        return [
            "The RDP server refused TLS or chose Standard RDP Security. Set the Security Layer to SSL (TLS) or "
            "Negotiate and require NLA (Group Policy › Remote Desktop Session Host › Security).",
            "SSL_CERT_NOT_ON_SERVER means the bound certificate is missing or NETWORK SERVICE cannot read its private "
            "key: re-bind it.",
            "A reply that is not TPKT means the port is not RDP: check the port and any RDP-aware proxy.",
        ]
    return ["The server accepted the connection but did not negotiate TLS. Confirm the port and service type."]


def _why(reason: Topic, host: str) -> str:
    return {
        Topic.EXPIRY: "Renew before expiry.",
        Topic.HOSTNAME: f"Reissue with every service name ({host}) in the SAN.",
        Topic.NO_SAN: f"Reissue with every service name ({host}) in the SAN.",
        Topic.EKU: "Reissue from a template/profile with Server Authentication EKU.",
        Topic.WEAK_KEY: "Reissue with RSA 2048+ or ECDSA P-256.",
        Topic.WEAK_SIGNATURE: "Reissue signed with SHA-256 or stronger.",
    }.get(reason, "Reissue or replace the certificate.")


def replace(p: Platform, host: str, reason: Topic) -> Guidance:
    why = _why(reason, host)
    q = shlex.quote
    base, csr_name = q(host + ".key"), q(host + ".csr")
    csr = (
        f"(umask 077 && {OPENSSL} req -new -newkey rsa:2048 -nodes -keyout {base} -out {csr_name} "
        f"-subj {q('/CN=' + host)} -addext {q('subjectAltName=DNS:' + host)}) && chmod 600 {base}"
        f"  # delete the .key after installing it: shred -u {base}"
    )
    match p:
        case Platform.PFSENSE:
            return Guidance("pfSense: replace via Cert Manager", [
                why,
                "System › Cert Manager › Certificates: renew (internal CA) or import the new certificate and key.",
                "Assign it where used: System › Advanced › Admin Access (GUI), VPN › IPsec › Phase 1 (IKEv2 "
                "'My Certificate'), or the service using it.",
                "For IPsec, also confirm clients trust the issuing CA and that the SAN matches the IKE identifier.",
            ], ["/etc/rc.restart_webgui", "swanctl --list-certs"])  # fmt: skip
        case Platform.WINDOWS_AD:
            return Guidance("Active Directory: replace the LDAPS certificate", [
                why,
                "Request a new certificate from the AD CS 'Domain Controller Authentication' or Kerberos template on "
                "the DC (certlm.msc › Personal › Request New Certificate).",
                "Remove the expired certificate after the new one is in place.",
                "Force LDAPS to load the new certificate without reboot using the LDIF below, then re-check LDAPS 636 "
                "and StartTLS 389.",
            ], ["certutil -store My", "certutil -verify -urlfetch new-dc.cer",
                'Set-Content renew.ldf "dn:`nchangetype: modify`nadd: renewServerCertificate`n'
                'renewServerCertificate: 1`n-"',
                "ldifde -i -f renew.ldf"])  # fmt: skip
        case Platform.WINDOWS_IIS:
            return Guidance("Windows IIS / RD Gateway: bind the new certificate", [
                why,
                "Import the PFX into Local Computer › Personal.",
                "IIS Manager › Site › Bindings › https › select the new certificate. For RD Gateway: RD Gateway "
                "Manager › Properties › SSL Certificate.",
            ], ["Get-ChildItem Cert:\\LocalMachine\\My | Select Subject, NotAfter, Thumbprint",
                "netsh http show sslcert"])  # fmt: skip
        case Platform.NGINX:
            return Guidance("nginx: deploy the new certificate", [
                why,
                "ssl_certificate must point to the full chain (leaf first); ssl_certificate_key to the matching key.",
                "Test the configuration before reloading.",
            ], [csr, "nginx -t && systemctl reload nginx"])  # fmt: skip
        case Platform.APACHE:
            return Guidance("Apache: deploy the new certificate", [
                why,
                "SSLCertificateFile should reference the full chain (Apache 2.4.8+); SSLCertificateKeyFile the "
                "matching key.",
            ], [csr, "apachectl configtest && systemctl reload apache2"])  # fmt: skip
        case Platform.ZIMBRA:
            return Guidance("Zimbra: verify and deploy with zmcertmgr", [
                why,
                "Place the key in /opt/zimbra/ssl/zimbra/commercial/commercial.key, then verify and deploy the "
                "certificate with its chain as the zimbra user.",
                "Restart Zimbra services in a maintenance window.",
            ], ["su - zimbra -c '/opt/zimbra/bin/zmcertmgr verifycrt comm "
                "/opt/zimbra/ssl/zimbra/commercial/commercial.key /tmp/cert.crt /tmp/ca_chain.crt'",
                "su - zimbra -c '/opt/zimbra/bin/zmcertmgr deploycrt comm /tmp/cert.crt /tmp/ca_chain.crt'",
                "su - zimbra -c 'zmcontrol restart'"])  # fmt: skip
        case Platform.MYSQL:
            return Guidance("MySQL: rotate the server certificate", [
                why,
                "Replace the files referenced by ssl_cert, ssl_key and ssl_ca, keeping ownership mysql:mysql and key "
                "mode 600.",
                "Reload TLS online (MySQL 8.0.16+), then confirm the new expiry.",
            ], ['mysql -e "ALTER INSTANCE RELOAD TLS;"',
                "mysql -e \"SHOW STATUS LIKE 'Ssl_server_not_after';\""])  # fmt: skip
        case Platform.SYNOLOGY:
            return Guidance("Synology DSM: replace the certificate", [
                why,
                "Control Panel › Security › Certificate › Add › Replace an existing certificate (import key, "
                "certificate and intermediate).",
                "Use Settings to assign the certificate to each service (DSM, WebDAV, Hyper Backup Vault…).",
            ])  # fmt: skip
        case Platform.PROXMOX_VE:
            return Guidance("Proxmox VE: install a custom certificate", [
                why,
                "Upload in the GUI (Node › System › Certificates) or use pvenode on the node.",
                "pveproxy restarts to load it; verify afterwards.",
            ], ["pvenode cert set fullchain.pem key.pem --restart 1 --force 1", "pvenode cert info"])  # fmt: skip
        case Platform.PROXMOX_BACKUP:
            return Guidance("Proxmox Backup Server: regenerate the self-signed certificate", [
                why,
                "Regenerating changes the fingerprint; update the fingerprint on every PVE storage entry afterwards.",
            ], ["proxmox-backup-manager cert update --force", "proxmox-backup-manager cert info | grep -i fingerprint",
                "pvesm set STORAGE_ID --fingerprint 'AA:BB:…'"])  # fmt: skip
        case Platform.MACOS:
            return Guidance("macOS: inspect the identity", [
                why,
                "Use Keychain Access to check the certificate and its private key are both present in the same "
                "keychain.",
            ], ["security find-identity -v", f"security find-certificate -a -c {q(host)} -p"])  # fmt: skip
        case _:
            return Guidance("Reissue and redeploy", [
                why,
                "Generate a CSR on the server (or the platform's own wizard), submit to the CA, deploy the full chain, "
                "and re-check here.",
            ], [csr])  # fmt: skip
