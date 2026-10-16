"""SCRAM reverse-engineering notes only.

No authentication request is sent by this module. The firmware's discovered algorithm
is non-standard; implementing it requires sanitized fixtures and local unit tests first.
See docs/PHASE2_STATUS.md before enabling any login flow.
"""

AUTH_ENDPOINT = "/api/user/challenge_login"
FINALIZE_ENDPOINT = "/api/user/authentication_login"


def build_scram_proof(*args, **kwargs):
    raise NotImplementedError(
        "SCRAM proof generation is intentionally gated until sanitized fixtures verify "
        "the firmware-specific algorithm."
    )
