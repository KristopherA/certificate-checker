FastAPI app (Jinja2 + htmx): routes in main.py, request hardening in security.py, login, sessions, lockout and rate limits in auth.py, the UI certificate in tlsboot.py, /config/ca in cabundle.py, in-memory form parsing in forms.py. Run with python -m app (TLS 1.2+ on 0.0.0.0:8080 and a login; python -m app hash-password makes the password hash). One worker, one event loop: all of this state is per process.

Notes (review M5 S2/S3):
- /api/v1/openapi.json needs a session since M6 (it was public in M5). Swagger/ReDoc are off (CSP).
- CSRF: an unsafe request is refused when Sec-Fetch-Site is cross-site or same-site, or when Origin is present and not this origin. There is no Referer fallback when Origin is missing; such requests still need the form CSRF token (UI) or a JSON body / X-CertCheck-Request header (API).
- At most CERTCHECK_MAX_CONCURRENT checks run at once; one more gets 429 straight away, never a queue. Each address also gets checks_per_minute checks (429 with Retry-After beyond it).
