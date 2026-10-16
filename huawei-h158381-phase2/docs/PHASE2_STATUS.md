# Phase 2 status and safety gates

## Confirmed from the Phase 1 report

- Firmware: `3.0.0.1(H3563SP3C1636)`.
- Modem UI: `https://192.168.70.1`.
- `/api/device/basic_information`, `/api/net/current-plmn`,
  `/api/monitoring/traffic-statistics`, `/api/dialup/connection`,
  `/api/dialup/mobile-dataswitch`, `/api/pin/status`, `/api/user/state-login`,
  `/api/global/module-switch`, `/api/webserver/SesTokInfo`, `/api/webserver/token`,
  `/api/monitoring/check-notifications` returned HTTP 200 in the read-only discovery.
- The firmware JavaScript indicates SCRAM challenge/finalization and RSA-protected write tokens.
- The scan start endpoint's method and side effects remain unknown.
- Authenticated cell, band, and scan schemas have not been independently validated in this phase.

## Implemented in this starter

- Exact-path GET allowlist for endpoints already reported as safe.
- Unknown and scan-related endpoints blocked before network access.
- HTTPS-only base URL and redirects disabled.
- XML parser and repeat-tag handling.
- Terminal-only hidden password prompt helper; it does not save credentials.
- Sanitized example fixtures and unit tests.

## Deliberately not implemented/enabled yet

1. No login POST is sent.
2. No POST of any kind is exposed by the API client.
3. No antenna scan is started.
4. No scan status/result endpoint is called until the firmware contract is checked.
5. No band lock, cell lock, network search, reconnect, reset, or reboot request is issued.
6. SCRAM proof generation remains a gated stub pending sanitized challenge fixtures and unit tests.

## Next safe steps on the user's machine

1. Review/merge the starter files into `H:\huawei-modem`; do not blindly overwrite existing files.
2. Create a venv, install development dependencies, and run `pytest`.
3. From the modem's own JS files, extract the exact GET behavior for `best-position-status`,
   `best-position-result`, and the authenticated cell-info API. Keep evidence sanitized.
4. Implement the firmware-specific SCRAM calculation as pure functions and test it only against
   sanitized fixtures. No live authentication call until the exact request is reviewed.
5. After authentication is separately cleared for execution, prompt for the password with
   `getpass`, perform the approved login exchange, and fetch admin JS chunks using GET only.
6. Review all candidate scan operations and their impact before asking for approval to run any.

## Evidence policy

Never persist real passwords, session cookies, CSRF tokens, RSA nonces, or full authentication
requests/responses. Keep real live evidence out of Git. Commit only sanitized schemas and fixtures.
