"""Probe service types, mirroring Service in Source/Sources/Core/Targets.swift (same raw values and ports)."""

from __future__ import annotations

import enum


class Service(enum.StrEnum):
    HTTPS = "HTTPS"
    TLS = "TLS (implicit)"
    LDAPS = "LDAPS"
    LDAP_STARTTLS = "LDAP StartTLS"
    SMTP_STARTTLS = "SMTP STARTTLS"
    SMTPS = "SMTPS"
    IMAP_STARTTLS = "IMAP STARTTLS"
    IMAPS = "IMAPS"
    POP3_STARTTLS = "POP3 STLS"
    POP3S = "POP3S"
    MYSQL = "MySQL TLS"
    RDP = "RDP (TLS)"
    RD_GATEWAY = "RD Gateway (HTTPS)"
    WINRM_HTTPS = "WinRM HTTPS"
    SYNOLOGY_DSM = "Synology DSM (HTTPS)"
    PROXMOX_VE = "Proxmox VE (HTTPS)"
    PROXMOX_BACKUP = "Proxmox Backup Server (HTTPS)"
    DOCKER_REGISTRY = "Docker registry (HTTPS)"
    LOGSTASH_BEATS = "Logstash Beats input (TLS)"
    ELASTICSEARCH = "Elasticsearch (HTTPS)"
    MUNKI_REPO = "Munki repo (HTTPS)"
    FILEMAKER = "FileMaker Server (TLS)"
    RETROSPECT_CONSOLE = "Retrospect web console (HTTPS)"
    HP_PRINTER = "HP printer EWS (HTTPS)"
    BARRACUDA_SERVICE = "Barracuda WAF service (HTTPS)"
    BARRACUDA_MANAGEMENT = "Barracuda WAF management (HTTPS)"

    @property
    def default_port(self) -> int:
        return _PORTS.get(self, 443)

    @property
    def uses_upgrade(self) -> bool:
        return self in _UPGRADE

    @property
    def is_remote_admin(self) -> bool:
        return self in (Service.RDP, Service.RD_GATEWAY, Service.WINRM_HTTPS)

    @property
    def accepts_fingerprint_pin(self) -> bool:
        return self in (Service.PROXMOX_BACKUP, Service.PROXMOX_VE)

    @property
    def is_appliance(self) -> bool:
        return self in (Service.SYNOLOGY_DSM, Service.PROXMOX_VE, Service.PROXMOX_BACKUP)

    @property
    def is_stack(self) -> bool:
        return self in (Service.DOCKER_REGISTRY, Service.LOGSTASH_BEATS, Service.ELASTICSEARCH)

    @property
    def is_vendor(self) -> bool:
        return self in (
            Service.MUNKI_REPO,
            Service.FILEMAKER,
            Service.RETROSPECT_CONSOLE,
            Service.HP_PRINTER,
            Service.BARRACUDA_SERVICE,
            Service.BARRACUDA_MANAGEMENT,
        )

    @property
    def openssl_starttls(self) -> str | None:
        return _STARTTLS.get(self)


_PORTS = {
    Service.LDAPS: 636,
    Service.LDAP_STARTTLS: 389,
    Service.SMTP_STARTTLS: 587,
    Service.SMTPS: 465,
    Service.IMAP_STARTTLS: 143,
    Service.IMAPS: 993,
    Service.POP3_STARTTLS: 110,
    Service.POP3S: 995,
    Service.MYSQL: 3306,
    Service.RDP: 3389,
    Service.WINRM_HTTPS: 5986,
    Service.SYNOLOGY_DSM: 5001,
    Service.PROXMOX_VE: 8006,
    Service.PROXMOX_BACKUP: 8007,
    Service.LOGSTASH_BEATS: 5044,
    Service.ELASTICSEARCH: 9200,
    Service.BARRACUDA_MANAGEMENT: 8443,
}
_UPGRADE = frozenset(
    {
        Service.LDAP_STARTTLS,
        Service.SMTP_STARTTLS,
        Service.IMAP_STARTTLS,
        Service.POP3_STARTTLS,
        Service.MYSQL,
        Service.RDP,
    }
)
_STARTTLS = {
    Service.SMTP_STARTTLS: "smtp",
    Service.IMAP_STARTTLS: "imap",
    Service.POP3_STARTTLS: "pop3",
    Service.LDAP_STARTTLS: "ldap",
    Service.MYSQL: "mysql",
}
