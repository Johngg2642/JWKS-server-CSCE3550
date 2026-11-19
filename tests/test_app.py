"""Endpoint, persistence, and SQL injection regression tests."""

import base64
import secrets
import time
from contextlib import closing
from unittest.mock import patch
from uuid import UUID

import jwt
import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import create_app
from storage import connect, decrypt_key, generate_key_pair, load_key_cipher


@pytest.fixture
def cipher(monkeypatch):
    monkeypatch.setenv("NOT_MY_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
    return load_key_cipher()


@pytest.fixture
def service(tmp_path, cipher):
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


def test_startup_schema_and_seed(service, cipher):
    records = rows(service)
    assert len(records) == 2
    assert any(r["exp"] <= time.time() for r in records)
    assert any(r["exp"] > time.time() for r in records)
    for row in records:
        assert isinstance(row["kid"], int)
        assert isinstance(row["key"], bytes)
        assert b"PRIVATE KEY" not in row["key"]
        pem = decrypt_key(row["key"], cipher)
        assert serialization.load_pem_private_key(pem, None).key_size == 2048
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
def test_expired_parameter_presence(client, service, cipher, query):
    token = client.post("/auth" + query).text
    kid = jwt.get_unverified_header(token)["kid"]
    row = next(r for r in rows(service) if str(r["kid"]) == kid)
    pem = decrypt_key(row["key"], cipher)
    public_key = serialization.load_pem_private_key(pem, None).public_key()
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


def test_jwks_all_valid_keys_and_expiry_boundary(client, service, cipher):
    with closing(connect(service.config["DATABASE"])) as connection, connection:
        generate_key_pair(connection, cipher)
        boundary_kid = generate_key_pair(connection, cipher)
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


def test_parameterized_insert_keeps_sql_like_data_literal(service, cipher):
    malicious_pem = b"'); DROP TABLE keys; --"
    with patch("storage.rsa.generate_private_key") as generate:
        generate.return_value.private_bytes.return_value = malicious_pem
        with closing(connect(service.config["DATABASE"])) as connection, connection:
            kid = generate_key_pair(connection, cipher)
            second_kid = generate_key_pair(connection, cipher)
            first, second = connection.execute(
                "SELECT key FROM keys WHERE kid IN (?, ?) ORDER BY kid",
                (kid, second_kid),
            ).fetchall()
            assert first["key"] != second["key"]
            assert decrypt_key(first["key"], cipher) == malicious_pem
            assert decrypt_key(second["key"], cipher) == malicious_pem
            modified = first["key"][:-1] + bytes([first["key"][-1] ^ 1])
            with pytest.raises(ValueError, match="Unable to decrypt"):
                decrypt_key(modified, cipher)
    assert len(rows(service)) == 4


def test_project_2_keys_are_migrated_in_place(service, cipher):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    expires = int(time.time()) + 7200
    with closing(connect(service.config["DATABASE"])) as connection, connection:
        kid = connection.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, expires)
        ).lastrowid

    restarted = create_app(service.config["DATABASE"])
    row = next(row for row in rows(restarted) if row["kid"] == kid)
    assert len(rows(service)) == 3
    assert row["exp"] == expires
    assert row["key"] != pem
    assert decrypt_key(row["key"], cipher) == pem
    token = restarted.test_client().post("/auth").text
    assert jwt.get_unverified_header(token)["kid"] == str(kid)
    jwt.decode(token, key.public_key(), algorithms=["RS256"])


@pytest.mark.parametrize("value", [None, "invalid!", "YQ=="])
def test_invalid_key_configuration_does_not_create_database(
    tmp_path, monkeypatch, value
):
    if value is None:
        monkeypatch.delenv("NOT_MY_KEY", raising=False)
    else:
        monkeypatch.setenv("NOT_MY_KEY", value)
    path = tmp_path / "keys.db"
    with pytest.raises(ValueError, match="NOT_MY_KEY must contain"):
        create_app(path)
    assert not path.exists()


def test_wrong_key_does_not_replace_existing_keys(service, monkeypatch):
    before = rows(service)
    monkeypatch.setenv("NOT_MY_KEY", base64.b64encode(secrets.token_bytes(32)).decode())
    with pytest.raises(ValueError, match="Unable to decrypt"):
        create_app(service.config["DATABASE"])
    assert rows(service) == before


def test_registration_and_auth_log(client, service):
    signup = {"username": "student", "email": "student@example.com"}
    response = client.post("/register", json=signup)
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store"
    password = response.json["password"]
    assert UUID(password).version == 4
    for details in (
        dict(signup, email="other@example.com"),
        dict(signup, username="other"),
    ):
        duplicate = client.post("/register", json=details)
        assert duplicate.status_code == 409
        assert "password" not in duplicate.json
    response = client.post(
        "/auth",
        json={"username": "student", "password": password},
        environ_overrides={"REMOTE_ADDR": "192.0.2.15"},
        headers={"X-Forwarded-For": "192.0.2.99"},
    )
    assert decode_from_jwks(client, response.text)["sub"] == "student"
    assert client.post("/auth").status_code == 200
    with closing(connect(service.config["DATABASE"])) as connection:
        user = connection.execute("SELECT * FROM users").fetchone()
        assert user["username"] == signup["username"]
        assert user["email"] == signup["email"]
        assert user["date_registered"]
        assert user["last_login"] is None
        assert user["password_hash"].startswith("$argon2id$")
        assert PasswordHasher().verify(user["password_hash"], password)
        known, unknown = connection.execute(
            "SELECT * FROM auth_logs ORDER BY id"
        ).fetchall()
        assert known["request_ip"] == "192.0.2.15"
        assert known["request_timestamp"]
        assert known["user_id"] == user["id"]
        assert unknown["user_id"] is None


@pytest.mark.parametrize("body", [[], {}, {"username": "student", "email": " "}])
def test_invalid_registration(client, body):
    assert client.post("/register", json=body).status_code == 400


def test_auth_rate_limit_reopens_window_and_only_logs_successes(client, service):
    with patch("app.time.monotonic", return_value=10) as clock:
        for _ in range(10):
            assert client.post("/auth").status_code == 200
        response = client.post("/auth")
        assert response.status_code == 429
        assert response.headers["Retry-After"] == "1"
        clock.return_value = 11
        assert client.post("/auth").status_code == 200
    with closing(connect(service.config["DATABASE"])) as connection:
        assert connection.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0] == 11


def test_failed_signing_does_not_log_an_auth_request(client, service):
    with patch("app.jwt.encode", side_effect=ValueError("signing failed")):
        with pytest.raises(ValueError, match="signing failed"):
            client.post("/auth")
    with closing(connect(service.config["DATABASE"])) as connection:
        assert connection.execute("SELECT COUNT(*) FROM auth_logs").fetchone()[0] == 0


@pytest.mark.parametrize(
    "path,method",
    [("/auth", "GET"), ("/.well-known/jwks.json", "POST"), ("/auth", "DELETE")],
)
def test_wrong_methods(client, path, method):
    assert client.open(path, method=method).status_code == 405
