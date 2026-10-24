# shared/

Data shared by the Mac app and Certificate Checker Web (web/). Both test suites read it.

## Layouts

The tools work in both layouts. `tools/swift_root.py` is the one root finder: it tries
`<root>/Sources`, then `<root>/Source/Sources`, and `export_findings.py`, `record-golden.sh` and
`web/tests/test_catalogue.py` all use it. A symlinked `Sources/` or `Source/` is refused.

| Layout | Mac app | Next to it |
|---|---|---|
| Public repo | `<root>/Sources`, `<root>/Tests`, `<root>/project.yml`, ... | `<root>/shared`, `<root>/web` |
| Working copy | `<root>/Source/Sources`, `<root>/Source/Tests`, ... | `<root>/shared`, `<root>/web` |

With neither present the catalogue freshness test skips locally and fails when `CI` is set.

| Path | What | How it is made |
|---|---|---|
| `findings.yaml` | Every finding the Swift code can emit: id, severity, topic, kind, title, detail, source file, `mac_only`. `{expr}` marks a runtime value. | `python3 shared/tools/export_findings.py` (stdlib only; reads the Swift `Sources/` found by `swift_root.py`, or a path given as the first argument). Both branches of a ternary severity/topic become separate rows. Any call it cannot catalogue is printed to stderr, and `--check` fails on it (or on a new, unregistered helper) as well as on staleness. |
| `web-findings.yaml` | Web-only findings with no Swift equivalent (M4: revocation, legacy TLS, AIA, CT), same entry shape as `findings.yaml`. Ids must not collide with `findings.yaml`; `web/tests/test_catalogue.py` checks that and that every `Finding("id"` in `web/certcheck` is in one of the two files. | By hand. |
| `fixtures/ca/` | Fixture CA (root + issuing CA) and 24 leaf cases, with `cases.json` (hostname, purpose, files, pinned time). Test-only keys in `keys/`; names use `example.test` and RFC 5737 addresses. | `uv run --python 3.12 --with cryptography shared/fixtures/make_fixture_ca.py`. Re-running reuses `keys/` and is byte-stable, so adding a case only needs that case recorded. Deleting `keys/` means re-recording all goldens. The script refuses to write into a non-empty folder without `cases.json`. |
| `golden/<case>.json` | The Mac verdict for each fixture case at `pinned_now` (2027-01-15T00:00:00Z): FileCheck findings (id, severity, topic, kind, title), chain fingerprints, and a SecTrust verdict anchored at the fixture root. | `shared/tools/record-golden.sh` on a Mac with Xcode (runs `GoldenExportTests`, skipped in normal `test.sh`). |

Notes
- The Mac's own "trust" finding uses the macOS store, so fixture chains read as untrusted there. `trust_fixture_anchor` is the verdict the web version (fixture root as its only anchor) should match.
- Titles contain dates from the app's display formatter. `record-golden.sh` pins TZ=UTC and en_US so they are stable (each golden records `recorded_tz` / `recorded_locale`). Parity compares `id`, `severity` and `topic`; titles are for reference.

## Test-only CA

`fixtures/ca/root.pem`, `fixtures/ca/intermediate.pem` and everything in `fixtures/ca/keys/` are
test material with published private keys. Never import them into a keychain, browser or system
trust store (see `fixtures/ca/keys/README`).

Secret scanning: `.gitleaks.toml` (repo root) exempts these keys from gitleaks' `private-key` rule
only, file by file. **CI must run gitleaks from the repo root** (`gitleaks dir .`); the allowlist
paths are root-anchored, so a scan from anywhere else reports every fixture. After adding, renaming
or removing a key fixture, run `python3 shared/tools/gitleaks_allowlist.py --write`; the web tests
run `--check` and fail on drift.

## Golden fields (M1)

- `chain_validity`: per chain certificate, `not_before` / `not_after` in ISO 8601 UTC. Displayed
  dates in titles and details stay localised (recorded with TZ=GMT, en_US).
- Catalogue titles with a ternary inside interpolation are resolved per row when the condition
  matches the row's `if` branch (e.g. `waf-selfsigned`); unrelated ternaries (plurals) stay `{…}`.

## Parity (M1)

`web/tests/test_parity.py` checks every case against its golden on finding id, severity and topic,
the chain fingerprints and validity, and the fixture-anchored trust verdict. Accepted Apple vs
OpenSSL differences live in `known-differences.yaml`; the test fails on anything unlisted or stale.
