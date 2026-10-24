"""Request bodies parsed fully in memory (the body is already capped by security.Hardening).

No python-multipart / SpooledTemporaryFile: an uploaded key or PFX never touches the disk, even briefly.
"""

from __future__ import annotations

import email.parser
import email.policy
from dataclasses import dataclass, field
from urllib.parse import parse_qs

MAX_FIELDS = 64
MAX_FILES = 8
MAX_FIELD_LEN = 4096


class FormError(ValueError):
    pass


@dataclass
class Form:
    fields: dict[str, str] = field(default_factory=dict)
    files: list[tuple[str, bytes]] = field(default_factory=list)  # (file name, content), in upload order

    def get(self, k: str, default: str = "") -> str:
        return self.fields.get(k, default)

    def flag(self, k: str) -> bool:
        return self.fields.get(k, "") in ("on", "1", "true")


def _field(form: Form, name: str, value: str) -> None:
    if len(form.fields) >= MAX_FIELDS or name in form.fields:
        raise FormError("Too many or repeated form fields.")
    if len(value) > MAX_FIELD_LEN:
        raise FormError(f"Form field {name} is too long.")
    form.fields[name] = value


def parse(content_type: str, body: bytes) -> Form:
    ctype = content_type.split(";", 1)[0].strip().lower()
    form = Form()
    if ctype == "application/x-www-form-urlencoded":
        try:
            pairs = parse_qs(body.decode("utf-8"), keep_blank_values=True, strict_parsing=False,
                             max_num_fields=MAX_FIELDS)  # fmt: skip
        except (UnicodeDecodeError, ValueError):
            raise FormError("The form could not be read.") from None
        for k, vs in pairs.items():
            if len(vs) != 1:
                raise FormError("Repeated form fields.")
            _field(form, k, vs[0])
        return form
    if ctype != "multipart/form-data":
        raise FormError("Expected a form submission.")
    msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
        b"Content-Type: " + content_type.encode("latin-1") + b"\r\nMIME-Version: 1.0\r\n\r\n" + body
    )
    if not msg.is_multipart():
        raise FormError("The upload could not be read.")
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str) or not name:
            raise FormError("The upload could not be read.")
        payload = part.get_payload(decode=True)
        data = payload if isinstance(payload, bytes) else b""
        filename = part.get_filename()
        if filename is not None:
            if not filename and not data:
                continue  # an empty file input
            if len(form.files) >= MAX_FILES:
                raise FormError(f"At most {MAX_FILES} files per check.")
            form.files.append((_safe_name(filename), data))
        else:
            try:
                _field(form, name, data.decode("utf-8"))
            except UnicodeDecodeError:
                raise FormError("Form fields must be UTF-8 text.") from None
    return form


def _safe_name(n: str) -> str:
    """The base name only, printable, at most 100 characters (it is shown in findings and used for the suffix)."""
    n = n.replace("\\", "/").rsplit("/", 1)[-1]
    n = "".join(c for c in n if c.isprintable())[:100]
    return n or "upload"
