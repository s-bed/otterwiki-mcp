"""Tests for server.py:main() — auth configuration with MultiAuth."""

from unittest.mock import patch, MagicMock

import pytest

from fastmcp.server.auth import MultiAuth, StaticTokenVerifier

import otterwiki_mcp.server as server_mod
from otterwiki_mcp.config import Config
from otterwiki_mcp.oauth_store import SQLiteOAuthProvider, StandaloneSQLiteOAuthProvider


# --- Minimal valid env for main() ---

VALID_ENV = {
    "OTTERWIKI_API_URL": "http://wiki.test:80",
    "OTTERWIKI_API_KEY": "test-key",
    "MCP_BASE_URL": "http://localhost:8090",
}


@pytest.fixture(autouse=True)
def isolated_auth_env(monkeypatch, tmp_path):
    for name in ("PLATFORM_DOMAIN", "CONSENT_URL", "MCP_PLATFORM_DB", "ROBOT_DB_PATH", "MCP_PORT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MCP_OAUTH_DB", str(tmp_path / "oauth.db"))


def _run_main(monkeypatch, extra_env=None, tmp_path=None):
    """Set env, patch mcp.run to prevent actually starting, then call main().

    Returns the auth object assigned to mcp.auth.
    """
    for k, v in VALID_ENV.items():
        monkeypatch.setenv(k, v)
    if extra_env:
        for k, v in extra_env.items():
            monkeypatch.setenv(k, v)
    # Ensure MCP_AUTH_TOKEN is absent unless explicitly provided
    if not extra_env or "MCP_AUTH_TOKEN" not in extra_env:
        monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    # Use a temp DB so tests don't leave mcp_oauth.db in the working dir
    if tmp_path is not None:
        monkeypatch.setenv("MCP_OAUTH_DB", str(tmp_path / "test_oauth.db"))

    with patch.object(server_mod.mcp, "run"):
        server_mod.main()

    return server_mod.mcp.auth


class TestAuthSetup:
    """main() constructs MultiAuth correctly based on env."""

    def test_multiauth_without_token(self, monkeypatch):
        """No MCP_AUTH_TOKEN -> MultiAuth with StandaloneSQLiteOAuthProvider (no PLATFORM_DOMAIN set), no verifiers."""
        monkeypatch.delenv("PLATFORM_DOMAIN", raising=False)
        monkeypatch.delenv("CONSENT_URL", raising=False)
        auth = _run_main(monkeypatch)

        assert isinstance(auth, MultiAuth)
        assert isinstance(auth.server, StandaloneSQLiteOAuthProvider)
        assert auth.verifiers == []

    def test_multiauth_with_token(self, monkeypatch):
        """MCP_AUTH_TOKEN set -> MultiAuth with StandaloneSQLiteOAuthProvider (no PLATFORM_DOMAIN) + StaticTokenVerifier."""
        monkeypatch.delenv("PLATFORM_DOMAIN", raising=False)
        monkeypatch.delenv("CONSENT_URL", raising=False)
        auth = _run_main(monkeypatch, extra_env={"MCP_AUTH_TOKEN": "my-secret-token"})

        assert isinstance(auth, MultiAuth)
        assert isinstance(auth.server, StandaloneSQLiteOAuthProvider)
        assert len(auth.verifiers) == 1
        assert isinstance(auth.verifiers[0], StaticTokenVerifier)

    def test_static_verifier_contains_token(self, monkeypatch):
        """The StaticTokenVerifier should accept the configured token."""
        token = "my-secret-token"
        auth = _run_main(monkeypatch, extra_env={"MCP_AUTH_TOKEN": token})

        verifier = auth.verifiers[0]
        assert token in verifier.tokens
        assert verifier.tokens[token]["client_id"] == "claude-code"
        assert verifier.tokens[token]["scopes"] == []

    def test_oauth_provider_base_url(self, monkeypatch):
        """StandaloneSQLiteOAuthProvider receives MCP_BASE_URL (PLATFORM_DOMAIN not set)."""
        monkeypatch.delenv("PLATFORM_DOMAIN", raising=False)
        monkeypatch.delenv("CONSENT_URL", raising=False)
        auth = _run_main(monkeypatch)
        # StandaloneSQLiteOAuthProvider stores base_url as AnyHttpUrl
        assert str(auth.server.base_url) == "http://localhost:8090/"

    def test_empty_token_treated_as_absent(self, monkeypatch):
        """An empty MCP_AUTH_TOKEN is falsy, so no StaticTokenVerifier."""
        auth = _run_main(monkeypatch, extra_env={"MCP_AUTH_TOKEN": ""})

        assert isinstance(auth, MultiAuth)
        assert auth.verifiers == []


class TestAuthVerification:
    """Verify that the constructed auth actually accepts/rejects tokens."""

    @pytest.mark.asyncio
    async def test_static_token_accepted(self, monkeypatch):
        """A valid bearer token should pass verification."""
        token = "test-bearer-token"
        auth = _run_main(monkeypatch, extra_env={"MCP_AUTH_TOKEN": token})

        result = await auth.verify_token(token)
        assert result is not None
        # MultiAuth may namespace client_id; the static verifier metadata is
        # checked separately above.
        assert result.token == token
        assert result.scopes == []

    @pytest.mark.asyncio
    async def test_wrong_token_rejected(self, monkeypatch):
        """An unknown bearer token should be rejected by all verifiers."""
        auth = _run_main(monkeypatch, extra_env={"MCP_AUTH_TOKEN": "correct-token"})

        result = await auth.verify_token("wrong-token")
        assert result is None


class TestMainSideEffects:
    """main() sets up client and lifespan correctly."""

    def test_wiki_client_created(self, monkeypatch):
        """main() should create a WikiClient with the config values."""
        _run_main(monkeypatch)

        assert server_mod.client is not None
        # Verify the client was configured with the right base URL
        assert str(server_mod.client._client.base_url).rstrip("/") == "http://wiki.test"

    def test_mcp_run_called_with_correct_args(self, monkeypatch):
        """main() calls mcp.run() with streamable-http transport and correct port."""
        for k, v in VALID_ENV.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
        monkeypatch.setenv("MCP_PORT", "9999")

        with patch.object(server_mod.mcp, "run") as mock_run:
            server_mod.main()
            mock_run.assert_called_once_with(
                transport="streamable-http", host="0.0.0.0", port=9999, stateless_http=True
            )

    def test_lifespan_set(self, monkeypatch):
        """main() attaches the _lifespan context manager to mcp."""
        _run_main(monkeypatch)
        assert server_mod.mcp._lifespan is server_mod._lifespan


class TestOAuthProviderSelection:
    """main() selects the correct OAuth provider based on PLATFORM_DOMAIN."""

    def test_no_platform_domain_uses_standalone_sqlite_provider(self, monkeypatch):
        """When PLATFORM_DOMAIN is not set, StandaloneSQLiteOAuthProvider is used."""
        monkeypatch.delenv("PLATFORM_DOMAIN", raising=False)
        monkeypatch.delenv("CONSENT_URL", raising=False)
        auth = _run_main(monkeypatch)

        assert isinstance(auth, MultiAuth)
        assert isinstance(auth.server, StandaloneSQLiteOAuthProvider)

    def test_platform_domain_set_uses_sqlite_provider(self, monkeypatch, tmp_path):
        """When PLATFORM_DOMAIN and CONSENT_URL are set and signing key exists, SQLiteOAuthProvider is used."""
        # Write a minimal PEM file so _load_signing_key succeeds
        key_file = tmp_path / "signing_key.pem"
        key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\n" + "x" * 64 + "\n-----END RSA PRIVATE KEY-----\n")
        monkeypatch.setenv("PLATFORM_DOMAIN", "example.com")
        monkeypatch.setenv("CONSENT_URL", "https://example.com/auth/oauth/consent")
        monkeypatch.setenv("SIGNING_KEY_PATH", str(key_file))
        auth = _run_main(monkeypatch, tmp_path=tmp_path)

        assert isinstance(auth, MultiAuth)
        assert isinstance(auth.server, SQLiteOAuthProvider)

    def test_consent_url_no_default(self, monkeypatch):
        """CONSENT_URL has no default value — Config.consent_url is None/empty when env var not set."""
        monkeypatch.delenv("CONSENT_URL", raising=False)
        cfg = Config()
        assert not cfg.consent_url  # must be None or empty string, not a robot.wtf URL

    def test_platform_domain_no_default(self, monkeypatch):
        """PLATFORM_DOMAIN has no default value — Config.platform_domain is None/empty when env var not set."""
        monkeypatch.delenv("PLATFORM_DOMAIN", raising=False)
        cfg = Config()
        assert not cfg.platform_domain  # must be None or empty string, not "robot.wtf"

    @pytest.mark.parametrize("setting", ["PLATFORM_DOMAIN", "CONSENT_URL"])
    def test_partial_platform_config_aborts(self, monkeypatch, setting):
        monkeypatch.setenv(setting, "example.com" if setting == "PLATFORM_DOMAIN" else "https://example.com/consent")
        with pytest.raises(SystemExit):
            _run_main(monkeypatch)

    def test_unwritable_database_aborts(self, monkeypatch, tmp_path):
        import sqlite3

        monkeypatch.setenv("MCP_OAUTH_DB", str(tmp_path / "missing" / "oauth.db"))
        with pytest.raises(sqlite3.OperationalError):
            _run_main(monkeypatch)

    def test_missing_platform_signing_key_aborts(self, monkeypatch, tmp_path):
        with pytest.raises(SystemExit):
            _run_main(monkeypatch, extra_env={
                "PLATFORM_DOMAIN": "example.com",
                "CONSENT_URL": "https://example.com/consent",
                "SIGNING_KEY_PATH": str(tmp_path / "missing.pem"),
            })
