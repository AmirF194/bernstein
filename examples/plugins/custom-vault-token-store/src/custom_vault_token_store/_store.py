"""HashiCorp Vault token-role secret store (worked example).

Worked example of the ``provide_secret_store`` hookspec and the
:class:`ExternalSecretStore` contract. Wires the broker to Vault's own
token-role machinery so every ``mint_credential`` call mints a genuinely
new, Vault-issued, short-lived token rather than handing back a static
KV value with no real expiry.

Naming: ``path`` is a Vault token role name (``vault:auth/token/roles/<path>``
via ``SecretRef``). The role must already exist in Vault
(``vault write auth/token/roles/<path> ...``); this plugin only mints
against it, it does not manage role configuration.

The HTTP transport is a small injectable seam (:class:`VaultTransport`)
so unit tests can run without a live Vault. The default transport uses
only :mod:`urllib.request`, no vendor SDK, per the contract's own
"no vendor SDKs in core" rule, extended here to keep this example
dependency-free too.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol

from bernstein.core.security.external_secret_store import (
    ExternalCredential,
    ExternalSecretStore,
    ExternalStoreError,
    SecretDescriptor,
)

logger = logging.getLogger(__name__)


class VaultTransport(Protocol):
    """One HTTP call against a Vault API path.

    Split out so tests substitute a fake transport instead of needing a
    live Vault server. ``method`` is ``"GET"`` or ``"POST"``; ``body``
    (when given) is serialised as JSON. Returns the parsed JSON response
    body, or ``None`` on a 204. Raises :class:`ExternalStoreError` on any
    non-2xx response or transport failure.
    """

    def __call__(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any] | None: ...


@dataclass
class VaultHttpTransport:
    """Default transport: plain ``urllib`` calls against a Vault server.

    Attributes:
        addr: Vault base URL, e.g. ``"http://127.0.0.1:8200"``.
        token: Vault token used to authenticate every call
            (``X-Vault-Token``). This plugin never logs it.
        timeout_seconds: Per-request socket timeout.
    """

    addr: str
    token: str
    timeout_seconds: float = 5.0

    def __call__(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any] | None:
        url = f"{self.addr.rstrip('/')}/v1/{path.lstrip('/')}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"X-Vault-Token": self.token, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise ExternalStoreError(f"vault {method} {path} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise ExternalStoreError(f"vault {method} {path} unreachable: {exc.reason}") from exc
        if not raw:
            return None
        return json.loads(raw)


class VaultTokenRoleStore(ExternalSecretStore):
    """:class:`ExternalSecretStore` backed by a Vault token role.

    ``path`` names a Vault token role (``auth/token/roles/<path>``).
    ``resolve`` checks the role exists. ``mint_credential`` calls
    ``auth/token/create/<path>`` so every mint is a fresh Vault-issued
    token with its own accessor and lease. ``report_revocation`` looks
    the accessor up; a missing accessor means the token is gone, which
    this store reports as revoked so the broker stops treating it as
    live.
    """

    store_id = "vault"

    def __init__(self, *, transport: VaultTransport) -> None:
        self._transport = transport

    def resolve(self, path: str) -> SecretDescriptor:
        try:
            role = self._transport("GET", f"auth/token/roles/{path}")
        except ExternalStoreError as exc:
            raise ExternalStoreError(f"vault token role {path!r} not found: {exc}") from exc
        if role is None:
            raise ExternalStoreError(f"vault token role {path!r} not found")
        data = role.get("data", {})
        max_ttl = int(data.get("token_explicit_max_ttl") or data.get("explicit_max_ttl") or 0)
        return SecretDescriptor(
            store_id=self.store_id,
            upstream_id=str(data.get("name", path)),
            revoked=False,
            expires_at=0.0 if max_ttl == 0 else time.time() + max_ttl,
        )

    def mint_credential(self, path: str, *, audience: str, ttl_seconds: int) -> ExternalCredential:
        body = {"ttl": f"{ttl_seconds}s"}
        if audience:
            body["display_name"] = _sanitize_display_name(audience)
        response = self._transport("POST", f"auth/token/create/{path}", body)
        if response is None:
            raise ExternalStoreError(f"vault token create/{path} returned no body")
        auth = response.get("auth")
        if not auth or not auth.get("client_token"):
            raise ExternalStoreError(f"vault token create/{path} returned no auth block")
        lease_duration = int(auth.get("lease_duration") or ttl_seconds)
        capped_ttl = min(ttl_seconds, lease_duration) if lease_duration else ttl_seconds
        return ExternalCredential(
            value=auth["client_token"],
            expires_at=time.time() + capped_ttl,
            upstream_id=str(auth.get("accessor", "")),
            audience=audience,
        )

    def report_revocation(self, path: str, *, upstream_id: str) -> bool:
        if not upstream_id:
            # No accessor to check against: fail closed, same direction
            # ExternalStoreError already fails in, treat as revoked.
            return True
        try:
            lookup = self._transport(
                "POST",
                "auth/token/lookup-accessor",
                {"accessor": upstream_id},
            )
        except ExternalStoreError as exc:
            # Vault returns 403/404 for an accessor it no longer knows
            # about: treat that as "already revoked", the case this
            # method exists to report, not as a transport failure.
            logger.debug("vault lookup-accessor %s treated as revoked: %s", upstream_id, exc)
            return True
        if lookup is None:
            return True
        ttl_remaining = lookup.get("data", {}).get("ttl", 0)
        return int(ttl_remaining or 0) <= 0


def _sanitize_display_name(audience: str) -> str:
    """Vault display names allow only ``[a-zA-Z0-9-_.]``; map anything else."""
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in audience)[:64]
