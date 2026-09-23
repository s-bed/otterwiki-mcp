"""Tests for platform_auth.py — per-wiki bearer token verification.

These validate the bridge between the robot.wtf platform DB (wikis table with
mcp_token_hash) and the MCP sidecar's auth path: tokens issued by the platform
UI are accepted, scoped to the wiki resolved from the Host header.
"""

import hashlib
import sqlite3

import pytest

from fastmcp.server.dependencies import _current_http_request
from starlette.datastructures import Headers
from starlette.requests import Request

from otterwiki_mcp.platform_auth import (
    PlatformTokenVerifier,
    _host_wiki_slug,
    _sha256_hex,
    platform_db_available,
)


def _make_db(tmp_path, *, wikis=None):
    """Create a robot.wtf-shaped SQLite DB with a wikis table."""
    db = tmp_path / "robot.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE wikis (
            slug TEXT PRIMARY KEY,
            owner_did TEXT NOT NULL,
            display_name TEXT NOT NULL,
            repo_path TEXT NOT NULL,
            mcp_token_hash TEXT NOT NULL,
            is_public INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            last_accessed TEXT NOT NULL,
            page_count INTEGER DEFAULT 0,
            disk_usage_bytes INTEGER DEFAULT 0
        );
        """
    )
    for slug, token in (wikis or [("cic", "cic-secret")]):
        conn.execute(
            "INSERT INTO wikis (slug, owner_did, display_name, repo_path,"
            " mcp_token_hash, created_at, last_accessed)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                slug,
                f"did:plc:{slug}",
                slug.title(),
                f"/srv/data/wikis/{slug}/repo",
                _sha256_hex(token),
                "2026-01-01",
                "2026-01-01",
            ),
        )
    conn.commit()
    conn.close()
    return db


def _request(host: str) -> Request:
    """Build a Starlette request with a Host header."""
    scope = {
        "type": "http",
        "headers": [(b"host", host.encode())],
        "method": "GET",
        "path": "/mcp",
    }
    req = Request(scope)
    return req


def _with_host(host: str):
    """Context-manager-friendly way to set the current HTTP request."""
    _current_http_request.set(_request(host))


class TestSha256Hex:
    def test_matches_platform(self):
        """_sha256_hex matches the platform's generate_mcp_token hashing."""
        assert _sha256_hex("abc") == hashlib.sha256(b"abc").hexdigest()


class TestPlatformDbAvailable:
    def test_missing_db(self, tmp_path):
        assert platform_db_available(str(tmp_path / "nope.db")) is False

    def test_wrong_schema(self, tmp_path):
        db = tmp_path / "bad.db"
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE other (x TEXT)")
        conn.commit()
        conn.close()
        assert platform_db_available(str(db)) is False

    def test_valid_db(self, tmp_path):
        db = _make_db(tmp_path)
        assert platform_db_available(str(db)) is True

    def test_empty_path(self):
        assert platform_db_available("") is False


class TestVerifier:
    @pytest.mark.asyncio
    async def test_valid_token_with_matching_host(self, tmp_path):
        db = _make_db(tmp_path)
        _with_host("cic.robot.wtf")
        verifier = PlatformTokenVerifier(str(db))
        result = await verifier.verify_token("cic-secret")
        assert result is not None
        assert result.client_id == "platform-wiki:cic"
        assert result.claims["wiki_slug"] == "cic"

    @pytest.mark.asyncio
    async def test_valid_token_mcp_subdomain_host(self, tmp_path):
        """Host like cic.mcp.robot.wtf must resolve the wiki slug the same way."""
        db = _make_db(tmp_path)
        _with_host("cic.mcp.robot.wtf")
        verifier = PlatformTokenVerifier(str(db))
        result = await verifier.verify_token("cic-secret")
        assert result is not None
        assert result.claims["wiki_slug"] == "cic"

    @pytest.mark.asyncio
    async def test_wrong_token_rejected(self, tmp_path):
        db = _make_db(tmp_path)
        _with_host("cic.robot.wtf")
        verifier = PlatformTokenVerifier(str(db))
        assert await verifier.verify_token("not-the-token") is None

    @pytest.mark.asyncio
    async def test_empty_token_rejected(self, tmp_path):
        db = _make_db(tmp_path)
        verifier = PlatformTokenVerifier(str(db))
        assert await verifier.verify_token("") is None

    @pytest.mark.asyncio
    async def test_cross_wiki_token_rejected(self, tmp_path):
        """A token for wiki X presented on wiki Y's host must be rejected."""
        db = _make_db(tmp_path, wikis=[("cic", "cic-secret"), ("other", "other-secret")])
        _with_host("cic.robot.wtf")
        verifier = PlatformTokenVerifier(str(db))
        assert await verifier.verify_token("other-secret") is None

    @pytest.mark.asyncio
    async def test_no_request_context_accepts_token(self, tmp_path):
        """Without an HTTP request (e.g. stdio), slug scoping is skipped."""
        db = _make_db(tmp_path)
        # Ensure no active request context leaks in
        try:
            _current_http_request.set(None)
        except Exception:
            pass
        verifier = PlatformTokenVerifier(str(db))
        result = await verifier.verify_token("cic-secret")
        assert result is not None

    @pytest.mark.asyncio
    async def test_missing_db_returns_none(self, tmp_path):
        verifier = PlatformTokenVerifier(str(tmp_path / "nope.db"))
        assert await verifier.verify_token("cic-secret") is None


class TestHostWikiSlug:
    def test_cyc_domain(self):
        _with_host("cic.robot.wtf")
        assert _host_wiki_slug() == "cic"

    def test_mcp_subdomain(self):
        _with_host("cic.mcp.robot.wtf")
        assert _host_wiki_slug() == "cic"

    def test_bare_domain(self):
        _with_host("robot.wtf")
        assert _host_wiki_slug() == ""