# Huawei H158-381 Best Pair — Phase 2 foundation

This package is deliberately **read-only by default**. It does not change modem settings,
start antenna scans, lock cells/bands, reconnect the modem, or submit any POST request.

## Setup (Windows PowerShell)

```powershell
cd H:\huawei-modem
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest
```

Copy these files into the existing `H:\huawei-modem` workspace after reviewing the diff;
do not overwrite existing files blindly.

## Safety contract

- `ReadOnlyModemClient` only permits a small explicit GET allowlist.
- No generic `request()` method is exposed.
- Mutating / unknown endpoints are rejected before network I/O.
- Scan status/result endpoints are marked **unverified** and are not enabled by default.
- Credentials are requested using `getpass` in a local terminal. They are never persisted.
- Do not paste passwords, session cookies, CSRF tokens, or RSA material into chat or logs.
- HTTPS certificate verification remains enabled by default. If the modem uses a locally
  issued certificate, configure a trusted CA path; do not disable verification casually.
- Bind any future local web UI to `127.0.0.1`, and keep credentials in the Python process,
  never browser JavaScript.

## Current Phase 2 boundary

The modem's own JS must be inspected before implementing its SCRAM login POST. Although the
login route and crypto flow were identified in the discovery report, this starter intentionally
does not execute login or any POST. First validate the SCRAM implementation against sanitized
fixtures and unit tests, then review the exact authentication request before enabling it.

Likewise, `/api/monitoring/best-signal-position` is not included because its method/side effects
are not confirmed. Do not call it until its contract and impact are established.

## Modules

- `src/huawei_tower/modem/api.py`: explicit GET-only client.
- `src/huawei_tower/modem/xmlutil.py`: safe XML parsing helpers.
- `src/huawei_tower/modem/security.py`: terminal-only password prompt and redaction.
- `src/huawei_tower/modem/errors.py`: typed exceptions.
- `evidence/fixtures/`: sanitized examples only.
- `docs/PHASE2_STATUS.md`: known facts and remaining gates.
