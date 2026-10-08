"""Endpoint, persistence, and SQL injection regression tests."""

import time
from contextlib import closing
from unittest.mock import patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from app import create_app
from storage import connect, generate_key_pair


@pytest.fixture
def service(tmp_path):
    app = create_app(tmp_path / "totally_not_my_privateKeys.db")
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(service):
    return service.test_client()


def rows(service):
    with closing(connect(service.config["DATABASE"])) as connection:
        return connection.execute("SELECT * FROM keys ORDER BY kid").fetchall()


def decode_from_jwks(client, token):
    kid = jwt.get_unverified_header(token)["kid"]
    key = next(
        k for k in client.get("/.well-known/jwks.json").json["keys"] if k["kid"] == kid
    )
    return jwt.decode(token, jwt.PyJWK.from_dict(key).key, algorithms=["RS256"])


def test_startup_schema_and_seed(service):
    records = rows(service)
    assert len(records) == 2
    assert any(r["exp"] <= time.time() for r in records)
    assert any(r["exp"] >= int(time.time()) + 3600 for r in records)
    for row in records:
        assert isinstance(row["kid"], int)
        assert isinstance(row["key"], bytes)
        assert row["key"].startswith(b"-----BEGIN RSA PRIVATE KEY-----")
        assert serialization.load_pem_private_key(row["key"], None).key_size == 2048
    with closing(connect(service.config["DATABASE"])) as connection:
        columns = connection.execute("PRAGMA table_info(keys)").fetchall()
        assert [(c["name"], c["type"]) for c in columns] == [
            ("kid", "INTEGER"),
            ("key", "BLOB"),
            ("exp", "INTEGER"),
        ]
        schema = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = ?", ("keys",)
        ).fetchone()[0]
        assert "AUTOINCREMENT" in schema


def test_auth_verifies_with_public_jwks(client, service):
    response = client.post("/auth")
    assert response.status_code == 200
    assert response.mimetype == "text/plain"
    payload = decode_from_jwks(client, response.text)
    assert payload["sub"] == "user123"
    assert payload["iss"] == "jwks-server"
    assert payload["exp"] > time.time()
    assert payload["iat"] <= time.time()
    assert len(rows(service)) == 2
    assert (
        jwt.get_unverified_header(client.post("/auth").text)["kid"]
        == jwt.get_unverified_header(response.text)["kid"]
    )


@pytest.mark.parametrize(
    "query", ["?expired", "?expired=true", "?expired=false", "?expired=1%20OR%201=1"]
)
def test_expired_parameter_presence(client, service, query):
    token = client.post("/auth" + query).text
    kid = jwt.get_unverified_header(token)["kid"]
    row = next(r for r in rows(service) if str(r["kid"]) == kid)
    public_key = serialization.load_pem_private_key(row["key"], None).public_key()
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public_key, algorithms=["RS256"])
    assert kid not in [
        k["kid"] for k in client.get("/.well-known/jwks.json").json["keys"]
    ]


@pytest.mark.parametrize("mode", ["basic", "json"])
def test_mock_auth_and_injection_input(client, service, mode):
    username = "userABC'; DROP TABLE keys; --"
    kwargs = (
        {"auth": (username, "password123")}
        if mode == "basic"
        else {"json": {"username": username, "password": "password123"}}
    )
    before = [(r["kid"], r["key"], r["exp"]) for r in rows(service)]
    assert (
        decode_from_jwks(client, client.post("/auth", **kwargs).text)["sub"] == username
    )
    assert [(r["kid"], r["key"], r["exp"]) for r in rows(service)] == before


@pytest.mark.parametrize("body", [[], {"username": 123}, {"username": ""}])
def test_mock_auth_invalid_username(client, body):
    assert (
        decode_from_jwks(client, client.post("/auth", json=body).text)["sub"]
        == "user123"
    )


def test_jwks_all_valid_keys_and_expiry_boundary(client, service):
    with closing(connect(service.config["DATABASE"])) as connection, connection:
        generate_key_pair(connection)
        boundary_kid = generate_key_pair(connection)
        now = int(time.time())
        connection.execute("UPDATE keys SET exp = ? WHERE kid = ?", (now, boundary_kid))
    with patch("app.time.time", return_value=now):
        response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    published = response.json["keys"]
    assert len(published) == 2
    assert str(boundary_kid) not in [key["kid"] for key in published]
    for key in published:
        assert set(key) == {"alg", "kty", "use", "kid", "n", "e"}
        assert (key["alg"], key["kty"], key["use"]) == ("RS256", "RSA", "sig")
        assert "=" not in key["n"] + key["e"]


def test_restart_preserves_keys_and_verifies_old_token(client, service):
    token = client.post("/auth").text
    before = [(r["kid"], r["key"], r["exp"]) for r in rows(service)]
    restarted = create_app(service.config["DATABASE"])
    assert [(r["kid"], r["key"], r["exp"]) for r in rows(restarted)] == before
    assert decode_from_jwks(restarted.test_client(), token)["sub"] == "user123"


@pytest.mark.parametrize("expired", [False, True])
def test_missing_key_category_is_regenerated(client, service, expired):
    with closing(connect(service.config["DATABASE"])) as connection, connection:
        connection.execute("DELETE FROM keys")
    assert client.get("/.well-known/jwks.json").json == {"keys": []}
    token = client.post("/auth" + ("?expired" if expired else "")).text
    assert len(rows(service)) == 1
    assert (rows(service)[0]["exp"] <= time.time()) is expired
    if not expired:
        assert decode_from_jwks(client, token)["sub"] == "user123"


def test_parameterized_insert_keeps_sql_like_data_literal(service):
    malicious_pem = b"'); DROP TABLE keys; --"
    with patch("storage.rsa.generate_private_key") as generate:
        generate.return_value.private_bytes.return_value = malicious_pem
        with closing(connect(service.config["DATABASE"])) as connection, connection:
            kid = generate_key_pair(connection)
            assert (
                connection.execute(
                    "SELECT key FROM keys WHERE kid = ?", (kid,)
                ).fetchone()[0]
                == malicious_pem
            )
    assert len(rows(service)) == 3


@pytest.mark.parametrize(
    "path,method",
    [("/auth", "GET"), ("/.well-known/jwks.json", "POST"), ("/auth", "DELETE")],
)
def test_wrong_methods(client, path, method):
    assert client.open(path, method=method).status_code == 405
