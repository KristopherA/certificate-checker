FastAPI app (Jinja2 + htmx): routes in main.py, request hardening in security.py, in-memory form parsing in forms.py. Run with python -m app (M5: loopback HTTP; TLS, LAN bind and login are M6).

Notes (review M5 S2/S3):
- /api/v1/openapi.json is public by design: it describes the API and holds no data. Swagger/ReDoc are off (CSP).
- CSRF: an unsafe request is refused when Sec-Fetch-Site is cross-site or same-site, or when Origin is present and not this origin. There is no Referer fallback when Origin is missing; such requests still need the form CSRF token (UI) or a JSON body / X-CertCheck-Request header (API).
- At most CERTCHECK_MAX_CONCURRENT checks run at once; one more gets 429 straight away, never a queue.
