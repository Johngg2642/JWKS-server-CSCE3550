import json
import time

import jwt
import pytest

from app import app, generate_key_pair, keys


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(autouse=True)
def run_around_tests():
    # Clear keys before each test
    keys.clear()
    yield


def test_jwks_returns_valid_keys_only(client):
    # Generate one valid and one expired key
    generate_key_pair(expired=False)
    generate_key_pair(expired=True)

    assert len(keys) == 2

    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200

    data = json.loads(response.data)
    assert "keys" in data
    jwks_keys = data["keys"]

    # Only 1 valid key should be returned
    assert len(jwks_keys) == 1

    # Verify the returned key structure
    key = jwks_keys[0]
    assert key["alg"] == "RS256"
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert "kid" in key
    assert "n" in key
    assert "e" in key

    # Check that it's the valid key
    valid_key_kid = next(k["kid"] for k in keys if k["exp"] > time.time())
    assert key["kid"] == valid_key_kid


def test_auth_returns_valid_jwt(client):
    response = client.post("/auth")
    assert response.status_code == 200

    token = response.data.decode("utf-8")

    # Should be decodeable without verification for just checking headers
    unverified_header = jwt.get_unverified_header(token)
    assert "kid" in unverified_header
    assert unverified_header["alg"] == "RS256"

    # Should have a single valid key in our keys store now
    assert len(keys) == 1
    valid_key = keys[0]

    # Decode to verify signature
    public_key = valid_key["private_key"].public_key()

    decoded_payload = jwt.decode(token, public_key, algorithms=["RS256"])

    assert "exp" in decoded_payload
    assert decoded_payload["exp"] > time.time()
    assert decoded_payload["iss"] == "jwks-server"


def test_auth_returns_expired_jwt(client):
    response = client.post("/auth?expired=true")
    assert response.status_code == 200

    token = response.data.decode("utf-8")

    # Should be decodeable without verification
    unverified_header = jwt.get_unverified_header(token)
    assert "kid" in unverified_header

    # Verify we created an expired key
    assert len(keys) == 1
    expired_key = keys[0]
    assert expired_key["exp"] < time.time()

    public_key = expired_key["private_key"].public_key()

    # Decoding should fail because it's expired
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public_key, algorithms=["RS256"])

    # But we can decode it without verification to check payload
    decoded_payload = jwt.decode(token, options={"verify_signature": False})
    assert decoded_payload["exp"] < time.time()
