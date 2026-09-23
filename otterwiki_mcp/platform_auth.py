"""Platform-wiki bearer token verification for the robot.wtf multi-tenant stack.

otterwiki-mcp runs as a sidecar (port 8001) alongside two other processes that
share one SQLite DB (``/srv/data/robot.db`` on production):

* port 8000 — the otterwiki wiki app behind ``TenantResolver``
* port 8002 — the robot.wtf management platform

The platform's *per-wiki* MCP bearer tokens are stored in the ``wikis`` table
as SHA-256 hashes (``mcp_token_hash`` column); the management UI issues them
("copy now, won't be shown again") and the resolver validates them via
``WikiModel.get_by_token()``.

Historically the MCP sidecar never consulted that DB — it only accepted the
single global ``MCP_AUTH_TOKEN`` env var — so tokens issued from the platform
UI (the ones operators actually hold) were rejected with 401. This module
bridges that gap: :class:`PlatformTokenVerifier` validates a bearer token
against the shared platform DB, scoped to the wiki resolved from the incoming
``Host`` header (exactly like the resolver's ``_resolve_bearer_token``:
token must belong to the wiki being served, or it is rejected).
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3

from fastmcp.server.auth.providers.jwt import TokenVerifier
from fastmcp.server.dependencies import get_http_request
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)

# Column names on the platform's wikis table (see robot.wtf schema.sql).
_WIKIS_TABLE = "wikis"
_SLUG_COLUMN = "slug"
_TOKEN_HASH_COLUMN = "mcp_token_hash"


def _sha256_hex(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def _host_wiki_slug() -> str:
    """Derive the wiki slug from the current request's Host header.

    Mirrors ``_set_host_from_request`` in server.py: the first label of a
    3+-part hostname is the wiki slug. Returns ``""`` if the header is
    missing or has no resolvable subdomain (callers treat that as "cannot
    scope the token to a wiki").
    """
    try:
        request = get_http_request()
    except RuntimeError:
        return ""  # No HTTP request context (e.g. stdio transport)
    host = request.headers.get("host", "")
    if not host:
        return ""
    hostname = host.split(":")[0]
    parts = hostname.split(".")
    if len(parts) < 3:
        return ""
    return parts[0]


class PlatformTokenVerifier(TokenVerifier):
    """Validate a bearer token against the platform's per-wiki token table.

    Enabled only when the sidecar can see the shared platform SQLite DB
    (``MCP_PLATFORM_DB`` env var / ``Config.platform_db``). Behaves like the
    resolver's ``_resolve_bearer_token``:

    * SHA-256 the presented token and look up ``wikis.mcp_token_hash``.
    * If no wiki matches → ``None`` (401 to the client).
    * If a wiki matches but its slug != the Host-derived slug → ``None``
      (token belongs to a different wiki; do not leak which one).
    * Otherwise returns an ``AccessToken`` scoped to that wiki slug.
    """

    def __init__(self, db_path: str, *_: object, **__: object) -> None:
        super().__init__()
        self._db_path = db_path

    async def verify_token(self, token: str) -> AccessToken | None:
        if not token:
            return None
        try:
            conn = sqlite3.connect(f"file:{self._db_path}?mode=ro", uri=True)
            try:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    f"SELECT {_SLUG_COLUMN} FROM {_WIKIS_TABLE}"
                    f" WHERE {_TOKEN_HASH_COLUMN} = ?",
                    (_sha256_hex(token),),
                ).fetchone()
            finally:
                conn.close()
        except sqlite3.Error as exc:
            logger.warning(
                "Platform DB lookup failed (path=%s): %s", self._db_path, exc
            )
            return None

        if row is None:
            return None

        slug = row[_SLUG_COLUMN]
        host_slug = _host_wiki_slug()
        if host_slug and slug != host_slug:
            logger.info(
                "Bearer token belongs to wiki %r but Host resolves to %r — rejecting",
                slug,
                host_slug,
            )
            return None

        return AccessToken(
            token=token,
            client_id=f"platform-wiki:{slug}",
            scopes=[],
            claims={"wiki_slug": slug, "iss": "robot.wtf-platform"},
        )


def platform_db_path_from_env() -> str:
    """Return the configured platform DB path, or "" when not set.

    Supports ``MCP_PLATFORM_DB`` (the canonical var for the sidecar); falls
    back to ``ROBOT_DB_PATH`` (used by the platform ansible/smoke tooling)
    for drop-in operability. Empty string means "feature disabled".
    """
    return os.environ.get("MCP_PLATFORM_DB") or os.environ.get("ROBOT_DB_PATH") or ""


def platform_db_available(db_path: str) -> bool:
    """True when the platform DB exists and has the expected table/column."""
    if not db_path:
        return False
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cols = {
                r[1]
                for r in conn.execute(
                    f"PRAGMA table_info({_WIKIS_TABLE})"
                ).fetchall()
            }
            return {_SLUG_COLUMN, _TOKEN_HASH_COLUMN}.issubset(cols)
        finally:
            conn.close()
    except sqlite3.Error:
        return False