"""Credential helpers shared by identity eligibility (core), the API and the scan-worker.

Replay *execution* and evidence building live in the scan-worker
(``sentinel_worker.modules.identity.authorization_replay``); only what several services need to
decide which test accounts are usable stays here.
"""
from __future__ import annotations

from sentinel_core.models.core import TestAccount
from sentinel_core.modules.identity.role_keys import authorization_role_key
from sentinel_core.modules.identity.test_account_secrets import TestAccountSecretCodec

ANONYMOUS_ROLE_KEYS = {"ANONYMOUS", "UNAUTHENTICATED", "PUBLIC", "GUEST"}
def is_anonymous_account(account: TestAccount | None) -> bool:
    return authorization_role_key(account) in ANONYMOUS_ROLE_KEYS
def auth_headers_for_account(account: TestAccount) -> dict[str, str]:
    """Return replayable auth headers for a configured test account."""

    auth_headers = TestAccountSecretCodec.auth_headers(account)
    if auth_headers:
        return auth_headers
    auth_token = TestAccountSecretCodec.auth_token(account)
    if auth_token:
        token = str(auth_token)
        if token.lower().startswith(("bearer ", "basic ")):
            return {"Authorization": token}
        return {"Authorization": f"Bearer {token}"}
    if is_anonymous_account(account):
        return {"Authorization": ""}
    return {}
