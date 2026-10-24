#!/usr/bin/env python3
"""Export the findings catalogue from the Swift sources to shared/findings.yaml.

Static extraction: every Finding(...) call and every per-module helper that builds one
(f, wg, add) is parsed with a small Swift string-literal scanner. Interpolations
"\\(expr)" become "{expr}". The output is deterministic (sorted) so a diff shows
catalogue drift. Read-only on the Swift sources; standard library only.

Usage: export_findings.py [SWIFT_SOURCES_DIR] [OUT_YAML] [--check]
  SWIFT_SOURCES_DIR defaults to Sources/ of the app found by swift_root.py (<root>/Sources in the
  public repo, <root>/Source/Sources in the working copy).
  --check: exit 1 if OUT_YAML differs from what would be written (CI drift gate).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from swift_root import SymlinkedSources, find_swift_root  # sibling module (sys.path above); stdlib-only script

SEVERITIES = ("pass", "info", "warning", "fail")
TOPICS_RE = re.compile(r"enum Topic: String, Codable, CaseIterable \{\s*case ([^}]*)\}")

# Helper name -> how to read its arguments. "args" lists the meaning of positional args
# after id and severity; "topic" is fixed when the helper hard-codes it.
HELPERS: dict[str, dict[str, dict]] = {
    "Radius.swift": {"f": {"args": ["kind", "title", "detail"], "topic": "radius"}},
    "Stack.swift": {"f": {"args": ["kind", "title", "detail"], "topic": "stack"}},
    "IPsec.swift": {"f": {"args": ["kind", "title", "detail"], "topic": "ipsec"}},
    "WireGuard.swift": {"wg": {"args": ["kind", "title", "detail"], "topic": "wireguard"}},
    "CodeSign.swift": {"f": {"args": ["topic", "title", "detail"], "kind": "codesign"}},
    "SMIME.swift": {"f": {"args": ["topic", "title", "detail"], "kind": "smime"}},
    "DKIM.swift": {"f": {"args": ["topic", "title", "detail"], "kind": "dkim"}},
    "SSHHostKeys.swift": {"f": {"args": ["topic", "title", "detail"], "kind": "ssh"}},
    "Vendor.swift": {
        "add": {"args": ["title", "detail", "kind"], "topic": "vendor"},
        "f": {"args": ["title", "detail"], "topic": "vendor", "kind": "munki-config"},
    },
}
FINDING = {"args": ["topic", "title", "detail"]}
MAC_ONLY_FILES = {"CodeSign.swift"}
MAC_ONLY_IDS = re.compile(r"^(pkg|codesign|private-relay)")  # split-dns has a web port (M2)


def read_string(src: str, i: int) -> tuple[str, int]:
    """src[i] is the opening quote. Returns (template, index after closing quote)."""
    assert src[i] == '"'
    i += 1
    out = []
    while i < len(src):
        c = src[i]
        if c == "\\":
            n = src[i + 1]
            if n == "(":
                expr, i = read_balanced(src, i + 2)
                out.append("{" + " ".join(expr.split()) + "}")
                continue
            out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(n, n))
            i += 2
            continue
        if c == '"':
            return "".join(out), i + 1
        out.append(c)
        i += 1
    raise ValueError("unterminated string")


def read_balanced(src: str, i: int) -> tuple[str, int]:
    """Read until the ')' matching an already-consumed '('. Returns (text, index after ')')."""
    depth, start = 1, i
    while i < len(src):
        c = src[i]
        if c == '"':
            _, i = read_string(src, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return src[start:i], i + 1
        i += 1
    raise ValueError("unbalanced")


def split_args(src: str, i: int) -> tuple[list[str], int]:
    """src[i-1] == '('. Returns raw top-level argument texts."""
    args, depth, start = [], 0, i
    while i < len(src):
        c = src[i]
        if c == '"':
            _, i = read_string(src, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                args.append(src[start:i].strip())
                return args, i + 1
            depth -= 1
        elif c == "," and depth == 0:
            args.append(src[start:i].strip())
            start = i + 1
        i += 1
    raise ValueError("unterminated call")


def top_level_split(expr: str, seps: str) -> list[tuple[str, str]]:
    """Split expr at top-level characters in seps (outside strings and brackets)."""
    out, depth, start, i = [], 0, 0, 0
    while i < len(expr):
        c = expr[i]
        if c == '"':
            _, i = read_string(expr, i)
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif (
            depth == 0 and c in seps and expr[i - 1 : i + 1] not in ("??", "?.") and expr[i : i + 2] not in ("??", "?.")
        ):
            out.append((expr[start:i], c))
            start = i + 1
        i += 1
    out.append((expr[start:], ""))
    return out


def render(expr: str) -> str:
    """Ternaries render as 'A | B' (both variants); otherwise see render_concat."""
    parts = top_level_split(expr, "?")
    if len(parts) == 2 and '"' in parts[1][0]:
        branches = top_level_split(parts[1][0], ":")
        if len(branches) == 2:
            return render(branches[0][0]) + " | " + render(branches[1][0])
    return render_concat(expr)


def render_concat(expr: str) -> str:
    """String-ish expression -> template. Literals and '+' concatenation become text with {expr} holes."""
    parts, i, cur = [], 0, ""
    expr = expr.strip()
    while i < len(expr):
        c = expr[i]
        if c == '"':
            if cur.strip().rstrip("+").strip():
                parts.append("{" + cur.strip().rstrip("+").strip() + "}")
            cur = ""
            s, i = read_string(expr, i)
            parts.append(s)
            while i < len(expr) and expr[i] in " +":
                i += 1
            continue
        cur += c
        i += 1
    if cur.strip():
        parts.append("{" + " ".join(cur.strip().lstrip("+").strip().split()) + "}")
    return "".join(parts)


def topics(core: Path) -> list[str]:
    m = TOPICS_RE.search((core / "Analysis.swift").read_text(encoding="utf-8"))
    if not m:
        raise SystemExit("Topic enum not found in Analysis.swift")
    return [t.strip() for t in m.group(1).split(",")]


def ternary(expr: str) -> tuple[str, str, str] | None:
    """'C ? A : B' at top level -> (C, A, B); None when expr is not a ternary."""
    q_parts = top_level_split(expr, "?")
    if len(q_parts) < 2:
        return None
    cond = q_parts[0][0].strip()
    rest = expr[len(q_parts[0][0]) + 1 :]
    depth_q, i = 0, 0
    # Find the ':' that pairs with the first '?', allowing nested ternaries in the true branch.
    parts = top_level_split(rest, "?:")
    for text, sep in parts:
        i += len(text) + 1
        if sep == "?":
            depth_q += 1
        elif sep == ":":
            if depth_q == 0:
                return cond, rest[: i - 1].strip(), rest[i:].strip()
            depth_q -= 1
    return None


def branches(expr: str) -> list[str]:
    """All leaf values of a (possibly nested) ternary, in order."""
    t = ternary(expr.strip())
    if not t:
        return [expr.strip()]
    return branches(t[1]) + branches(t[2])


def pick(expr: str, cond: str | None, side: int, ctx: dict[str, str] | None = None) -> str:
    """When expr is a ternary on the same condition as the row split, take that branch.
    ctx maps a resolved local (e.g. `topic`) to this row's value, so `topic == .startTLS ? A : B` resolves too."""
    t = ternary(expr.strip())
    if not t:
        return expr
    if cond is not None and t[0] == cond:
        return t[1 + side]
    eq = re.fullmatch(r"(\w+)\s*==\s*(\.\w+)", t[0])
    if eq and ctx and eq.group(1) in ctx:
        return t[1] if ctx[eq.group(1)] == eq.group(2) else t[2]
    return expr


def holes(text: str) -> list[tuple[int, int]]:
    """Spans of top-level {expr} holes in a rendered template, skipping braces inside string literals."""
    out, depth, start, i, quote = [], 0, 0, 0, False
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            quote = not quote
        elif not quote and c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif not quote and c == "}" and depth:
            depth -= 1
            if depth == 0:
                out.append((start, i + 1))
        i += 1
    return out


def resolve_holes(text: str, cond: str | None, side: int, ctx: dict[str, str]) -> str:
    """Per row, replace an interpolated ternary on this row's condition with the chosen literal branch.
    Ternaries on any other condition (e.g. plural 's') stay as {cond ? a : b}."""
    for a, b in reversed(holes(text)):
        inner = text[a + 1 : b - 1]
        chosen = pick(inner, cond, side, ctx)
        if chosen is inner or chosen == inner:
            continue
        lit = chosen.strip()
        if lit.startswith('"') and lit.endswith('"'):
            text = text[:a] + render(lit) + text[b:]
    return text


def enum_value(expr: str) -> str:
    return " | ".join(b.lstrip(".") if b.startswith(".") else "{" + b + "}" for b in branches(expr))


def resolve_local(expr: str, src: str, at: int, typ: str) -> str:
    """A plain identifier (e.g. `sev`, `topic`) is resolved from its nearest preceding `let NAME[: typ] = ...`."""
    if re.fullmatch(r"[A-Za-z_]\w*", expr):
        decls = list(re.finditer(r"\blet\s+" + expr + r"\s*(?::\s*" + typ + r")?\s*=\s*([^\n;]+)", src[:at]))
        if decls:
            return decls[-1].group(1).strip()
    return expr


def check_helpers(path: Path, src: str) -> list[str]:
    """Fail closed: any func that takes a Severity and builds a Finding must be listed in HELPERS."""
    problems = []
    known = HELPERS.get(path.name, {})
    for m in re.finditer(r"func\s+(\w+)\(([^)]*)\)([^\n]*)", src):
        name, params, tail = m.groups()
        if not re.search(r":\s*Severity\b", params) or not ("Finding(" in tail or "-> Finding" in tail):
            continue
        if name not in known:
            problems.append(f"{path.name}: helper {name}(...) builds Finding but is not in HELPERS")
    return problems


def extract(sources: Path, skips: list[str] | None = None) -> list[dict]:
    skips = skips if skips is not None else []
    sev_re = re.compile(r"\.({})".format("|".join(SEVERITIES)))
    rows: dict[tuple, dict] = {}
    for path in sorted(p for p in sources.rglob("*.swift") if not p.name.startswith("._")):
        src = path.read_text(encoding="utf-8")
        rel = path.relative_to(sources).as_posix()
        skips.extend(check_helpers(path, src))
        helpers = {"Finding": FINDING, **HELPERS.get(path.name, {})}
        pat = re.compile(r"(?<![A-Za-z0-9_.])(" + "|".join(map(re.escape, helpers)) + r")\(")
        for m in pat.finditer(src):
            line_start = src.rfind("\n", 0, m.start()) + 1
            line_no = src.count("\n", 0, m.start()) + 1
            if re.search(r"\bfunc\s*$", src[line_start : m.start()]):
                continue  # the helper's own declaration
            where = f"{rel}:{line_no}"
            line = src[line_start : src.find("\n", m.start())]
            decl = re.search(r"\bfunc\s+(\w+)\(", line)
            if m.group(1) == "Finding" and decl and decl.group(1) in HELPERS.get(path.name, {}):
                continue  # the body of a registered helper declaration (its calls are catalogued instead)
            try:
                args, _ = split_args(src, m.end())
            except ValueError as e:
                skips.append(f"{where}: cannot parse call ({e})")
                continue
            if len(args) < 3:
                skips.append(f"{where}: fewer than 3 arguments")
                continue
            spec = helpers[m.group(1)]
            pos = [a for a in args[2:] if not re.match(r"kind\s*:", a)]
            named_kind = next(
                (re.match(r"kind\s*:\s*(.*)$", a, re.S).group(1) for a in args[2:] if re.match(r"kind\s*:", a)), None
            )  # type: ignore[union-attr]
            sev_expr = resolve_local(args[1], src, m.start(), "Severity")
            st = ternary(sev_expr)
            topic_i = spec["args"].index("topic") if "topic" in spec["args"] else None
            topic_var = pos[topic_i] if topic_i is not None and topic_i < len(pos) else ""
            if topic_var and re.fullmatch(r"[A-Za-z_]\w*", topic_var):
                pos[topic_i] = resolve_local(topic_var, src, m.start(), "Topic")  # type: ignore[index]
            tt = ternary(pos[topic_i]) if topic_i is not None and topic_i < len(pos) else None
            # Split into one row per branch of the severity ternary, else of a topic ternary.
            if st:
                cond, variants = st[0], [(0, st[1]), (1, st[2])]
            elif tt:
                cond, variants = tt[0], [(0, sev_expr), (1, sev_expr)]
            else:
                cond, variants = None, [(0, sev_expr)]
            for side, sev in variants:
                sevs = branches(sev)
                if not all(sev_re.fullmatch(b) for b in sevs):
                    skips.append(f"{where}: severity {args[1]!r} is not a literal or resolvable ternary")
                    break
                for one in sevs:
                    rec = {
                        "id": render(args[0]),
                        "severity": one[1:],
                        "topic": spec.get("topic", ""),
                        "kind": spec.get("kind", ""),
                    }
                    ctx = {}
                    if tt and topic_var:
                        ctx[topic_var] = pick(pos[topic_i], cond, side).strip()  # type: ignore[index]
                    for name, a in zip(spec["args"], pos, strict=False):
                        a = pick(a, cond, side, ctx)
                        if name == "topic":
                            rec["topic"] = enum_value(a)
                        elif (
                            name == "kind"
                            and a.lstrip().startswith(".")
                            or name == "kind"
                            and ternary(a)
                            and all(b.startswith(".") for b in branches(a))
                        ):
                            rec["kind"] = enum_value(a)
                        else:
                            rec[name] = resolve_holes(render(a), cond, side, ctx)
                    if named_kind is not None:
                        rec["kind"] = render(pick(named_kind, cond, side))
                    rec.setdefault("detail", "")
                    rec["source"] = rel
                    rec["mac_only"] = (
                        path.name in MAC_ONLY_FILES or bool(MAC_ONLY_IDS.match(rec["id"])) or rel.startswith("App/")
                    )
                    key = (rec["id"], rec["severity"], rec["topic"], rec.get("title", ""))
                    if key in rows:
                        if rel not in rows[key]["source"].split(", "):
                            rows[key]["source"] += ", " + rel
                        continue
                    rows[key] = rec
    return sorted(
        rows.values(), key=lambda r: (r["topic"], r["id"], SEVERITIES.index(r["severity"]), r.get("title", ""))
    )


def q(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)  # JSON strings are valid YAML scalars


def to_yaml(sources: Path, rows: list[dict]) -> str:
    out = [
        "# Certificate Checker findings catalogue. GENERATED by shared/tools/export_findings.py"
        " from the Swift Sources/.",
        "# Do not edit by hand: change the Swift source and re-export. {expr} marks a runtime value.",
        "# mac_only: produced only by Mac-specific code (codesign/pkg, app-only paths); the web version may omit it.",
        "schema: 1",
        "severities: [" + ", ".join(SEVERITIES) + "]",
        "topics: [" + ", ".join(topics(sources / "Core")) + "]",
        f"count: {len(rows)}",
        "findings:",
    ]
    for r in rows:
        out.append(f"  - id: {q(r['id'])}")
        for k in ("severity", "topic", "kind", "title", "detail", "source"):
            out.append(f"    {k}: {q(r.get(k, ''))}")
        out.append(f"    mac_only: {'true' if r['mac_only'] else 'false'}")
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv
    argv = [a for a in argv if a != "--check"]
    here = Path(__file__).resolve().parents[2]
    if argv:
        sources = Path(argv[0])
    else:
        try:
            app = find_swift_root(here)
        except SymlinkedSources as e:
            print(e, file=sys.stderr)
            return 1
        if app is None:
            print(f"no Swift sources under {here} (tried Sources/ and Source/Sources/)", file=sys.stderr)
            return 1
        sources = app / "Sources"
    out = Path(argv[1]) if len(argv) > 1 else here / "shared" / "findings.yaml"
    skips: list[str] = []
    text = to_yaml(sources, extract(sources, skips))
    for msg in skips:
        print(f"skipped: {msg}", file=sys.stderr)
    if check:
        if skips:
            print(f"{len(skips)} call(s) could not be catalogued; fix the exporter or HELPERS", file=sys.stderr)
            return 1
        if not out.exists() or out.read_text(encoding="utf-8") != text:
            print(f"findings catalogue is stale: re-run {Path(__file__).name}", file=sys.stderr)
            return 1
        print(f"ok  {out} is current")
        return 0
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out} ({text.count(chr(10) + '  - id:')} findings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
