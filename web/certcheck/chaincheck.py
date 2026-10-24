"""Protocol-neutral chain helpers for the RADIUS, IPsec and mTLS checks (ChainCheck.swift).

verify() is stricter than the Mac. ChainCheck.verify passes the top certificate to SecTrust as its own anchor,
so a chain whose top certificate's issuer was never supplied "verifies" (a false PASS: Radius.swift:92-93 and
IPsec.swift srvN-chain). Here the top must be self-issued with a valid self-signature, or be (or be signed by)
a supplied anchor. See shared/known-differences.yaml (offline_differences).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence

from . import analysis
from .adjust import _anchored, _is_self_signed, _signed_by, build_chain
from .x509info import Cert

APPLE_RULE_START = dt.datetime(2019, 7, 1, tzinfo=dt.UTC)

is_self_signed = _is_self_signed
chain = build_chain


def cert_sign_allowed(c: Cert) -> bool:
    """RFC 5280 4.2.1.3: with a Key Usage present, keyCertSign (bit 5) must be set to sign certificates."""
    bits = c.key_usage_bits
    return bits is None or (len(bits) > 0 and bool(bits[0] & 0x04))


def verify(ch: Sequence[Cert], now: dt.datetime, anchors: Sequence[Cert] = ()) -> tuple[bool, str]:
    """Signatures link by link, every certificate in date, issuers are CAs, and the top is anchored. No network."""
    if not ch:
        return False, "No certificate."
    for c in ch:
        if not (c.not_before <= now <= c.not_after):
            return (
                False,
                f"{c.display_name} is outside its validity period "
                f"({analysis.fmt(c.not_before)} to {analysis.fmt(c.not_after)}).",
            )
    for child, parent in zip(ch, ch[1:], strict=False):
        if parent.is_ca is not True:
            return False, f"{parent.display_name} is not a CA certificate."
        if not cert_sign_allowed(parent):
            return False, f"{parent.display_name} has a Key Usage without keyCertSign, so it may not sign certificates."
        if not _signed_by(child, parent):
            return False, f"The signature on {child.display_name} does not verify with {parent.display_name}'s key."
    # RFC 5280 4.2.1.9: pathLenConstraint counts the non-self-issued intermediates below a CA (SecTrust enforces it).
    for j in range(1, len(ch)):
        limit = ch[j].path_len
        below = sum(1 for c in ch[1:j] if not c.is_self_issued)
        if limit is not None and below > limit:
            return (
                False,
                f"{ch[j].display_name} allows {limit} intermediate CA(s) below it (pathLenConstraint), "
                f"but the chain has {below}.",
            )
    top = ch[-1]
    outside = next(
        (
            a
            for a in anchors
            if a.der != top.der and not (top.is_self_issued and _signed_by(top, top)) and _signed_by(top, a)
        ),
        None,
    )
    if outside is not None:  # review S4: an anchor that sits above the chain constrains it too
        below = sum(1 for c in ch[1:] if not c.is_self_issued)
        if outside.is_ca is not True or not cert_sign_allowed(outside):
            return False, f"The anchor {outside.display_name} is not a CA allowed to sign certificates."
        if outside.path_len is not None and below > outside.path_len:
            return (
                False,
                f"The anchor {outside.display_name} allows {outside.path_len} intermediate CA(s) below it "
                f"(pathLenConstraint), but the chain has {below}.",
            )
    if not _anchored(top, anchors):
        if top.is_self_issued:
            return False, f"The self-signature on {top.display_name} does not verify."
        return (
            False,
            f"{top.display_name} was issued by {top.issuer_text}, which was not supplied, "
            "so the chain has no trusted root.",
        )
    return True, ""
