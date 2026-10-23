"""Core value types, mirroring Source/Sources/Core/Analysis.swift (Severity, Topic, Finding, Purpose)."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Severity(enum.IntEnum):
    PASS = 0
    INFO = 1
    WARNING = 2
    FAIL = 3

    @property
    def label(self) -> str:
        return self.name.lower()


class Topic(enum.StrEnum):
    EXPIRY = "expiry"
    HOSTNAME = "hostname"
    CHAIN_ORDER = "chainOrder"
    CHAIN_INCOMPLETE = "chainIncomplete"
    TRUST = "trust"
    KEY_MISMATCH = "keyMismatch"
    WEAK_KEY = "weakKey"
    WEAK_SIGNATURE = "weakSignature"
    EKU = "eku"
    CA_LEAF = "caLeaf"
    NO_SAN = "noSAN"
    LONG_VALIDITY = "longValidity"
    START_TLS = "startTLS"
    CONNECTION = "connection"
    CSR = "csr"
    GENERAL = "general"


class Purpose(enum.StrEnum):
    TLS_SERVER = "TLS server"
    TLS_CLIENT = "TLS client"
    ANY = "Any purpose"


@dataclass(frozen=True)
class Finding:
    id: str
    severity: Severity
    topic: Topic
    title: str
    detail: str = ""
    kind: str = ""

    def key(self) -> tuple[str, str, str]:
        """What parity compares with the Mac goldens."""
        return (self.id, self.severity.label, self.topic.value)

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "severity": self.severity.label,
            "topic": self.topic.value,
            "kind": self.kind,
            "title": self.title,
            "detail": self.detail,
        }


def sort_findings(fs: list[Finding]) -> list[Finding]:
    """Worst first, then by id (the Swift sort)."""
    return sorted(fs, key=lambda f: (-f.severity, f.id))
