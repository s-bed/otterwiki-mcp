"""Standalone OAuth survives process replacement without platform consent."""

import asyncio
import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import pytest
from mcp.server.auth.provider import AuthorizeError, TokenError
from mcp.server.auth.settings import ClientRegistrationOptions
from fastmcp import FastMCP
from fastmcp.server.auth import MultiAuth
from starlette.testclient import TestClient

from otterwiki_mcp.oauth_store import StandaloneSQLiteOAuthProvider
from tests.test_oauth_store import _make_auth_params, _make_client


BASE_URL = "https://otterwiki.example.com:11443"
RESOURCE = BASE_URL + "/mcp"


def _provider(db):
    return StandaloneSQLiteOAuthProvider(
        str(db), base_url=BASE_URL,
        client_registration_options=ClientRegistrationOptions(enabled=True),
    )


@pytest.mark.asyncio
async def test_clients_codes_tokens_and_revocation_survive_restarts(tmp_path):
    db = tmp_path / "oauth.db"
    provider = _provider(db)
    client = _make_client()
    client.scope = "read"
    await provider.register_client(client)

    provider = _provider(db)
    client = await provider.get_client(client.client_id)
    redirect = await provider.authorize(client, _make_auth_params(
        scopes=["read", "write"], resource=RESOURCE,
        redirect_uri_provided_explicitly=False,
    ))
    query = parse_qs(urlparse(redirect).query)
    assert query["state"] == ["test-state"]
    code = query["code"][0]

    provider = _provider(db)
    auth_code = await provider.load_authorization_code(client, code)
    assert auth_code.scopes == ["read"]
    assert auth_code.resource == RESOURCE
    assert auth_code.redirect_uri_provided_explicitly is False
    tokens = await provider.exchange_authorization_code(client, auth_code)

    provider = _provider(db)
    assert await provider.load_authorization_code(client, code) is None
    with pytest.raises(TokenError, match="already used"):
        await provider.exchange_authorization_code(client, auth_code)
    access = await provider.verify_token(tokens.access_token)
    assert access.resource == RESOURCE
    refresh = await provider.load_refresh_token(client, tokens.refresh_token)
    assert refresh is not None
    rotated = await provider.exchange_refresh_token(client, refresh, ["read"])

    provider = _provider(db)
    assert await provider.verify_token(tokens.access_token) is None
    assert await provider.load_refresh_token(client, tokens.refresh_token) is None
    access = await provider.verify_token(rotated.access_token)
    assert access.resource == RESOURCE
    await provider.revoke_token(access)

    provider = _provider(db)
    assert await provider.verify_token(rotated.access_token) is None
    assert await provider.load_refresh_token(client, rotated.refresh_token) is None


@pytest.mark.asyncio
async def test_unregistered_client_and_invalid_redirect_rejected(tmp_path):
    provider = _provider(tmp_path / "oauth.db")
    client = _make_client()
    with pytest.raises(AuthorizeError):
        await provider.authorize(client, _make_auth_params())
    await provider.register_client(client)
    with pytest.raises(AuthorizeError):
        await provider.authorize(client, _make_auth_params(redirect_uri="https://wrong.example.com/callback"))


def test_http_registration_pkce_and_token_exchange_across_restarts(tmp_path):
    db = tmp_path / "oauth.db"
    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

    def http_client():
        app = FastMCP(
            "OAuth restart test", auth=MultiAuth(server=_provider(db), verifiers=[])
        ).http_app(stateless_http=True)
        return TestClient(app, base_url=BASE_URL)

    with http_client() as http:
        metadata = http.get("/.well-known/oauth-authorization-server").json()
        assert metadata["token_endpoint"] == BASE_URL + "/token"
        resource = http.get("/.well-known/oauth-protected-resource/mcp").json()
        assert resource["resource"] == RESOURCE
        response = http.post("/register", json={
            "client_name": "Restart regression test",
            "redirect_uris": ["http://localhost/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        })
        assert response.status_code == 201, response.text
        registration = response.json()

    with http_client() as http:
        response = http.get("/authorize", params={
            "client_id": registration["client_id"],
            "redirect_uri": "http://localhost/callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "restart-state",
            "resource": RESOURCE,
        }, follow_redirects=False)
        assert response.status_code == 302, response.text
        redirect = urlparse(response.headers["location"])
        assert redirect.netloc == "localhost"
        query = parse_qs(redirect.query)
        assert query["state"] == ["restart-state"]
        code = query["code"][0]

    token_request = {
        "client_id": registration["client_id"],
        "client_secret": registration["client_secret"],
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": "http://localhost/callback",
        "code_verifier": verifier,
        "resource": RESOURCE,
    }
    with http_client() as http:
        wrong = http.post("/token", data={**token_request, "code_verifier": "wrong" * 16})
        assert wrong.status_code in (400, 401), wrong.text
        assert wrong.json()["error"] == "invalid_grant"
        response = http.post("/token", data=token_request)
        assert response.status_code == 200, response.text
        tokens = response.json()
        replay = http.post("/token", data=token_request)
        assert replay.status_code in (400, 401)
        assert replay.json()["error"] == "invalid_grant"

    provider = _provider(db)
    access = asyncio.run(provider.verify_token(tokens["access_token"]))
    assert access is not None
    assert access.resource == RESOURCE
    with http_client() as http:
        response = http.post("/token", data={
            "client_id": registration["client_id"],
            "client_secret": registration["client_secret"],
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
        })
        assert response.status_code == 200, response.text
        rotated = response.json()
    provider = _provider(db)
    assert asyncio.run(provider.verify_token(tokens["access_token"])) is None
    access = asyncio.run(provider.verify_token(rotated["access_token"]))
    assert access.resource == RESOURCE

    with http_client() as http:
        response = http.post("/mcp", json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26", "capabilities": {},
                "clientInfo": {"name": "restart-test", "version": "1"},
            },
        }, headers={
            "Authorization": "Bearer " + rotated["access_token"],
            "Accept": "application/json, text/event-stream",
        })
        assert response.status_code == 200, response.text
