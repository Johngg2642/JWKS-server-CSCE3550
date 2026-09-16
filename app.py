import base64
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

app = Flask(__name__)

# In-memory key storage
keys = []


def generate_key_pair(expired=False):
    """Generates an RSA key pair and stores it in memory."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    kid = str(uuid.uuid4())
    # 1 hour expiration for valid, or expired 1 hour ago
    exp_offset = -3600 if expired else 3600
    exp = int(time.time()) + exp_offset

    keys.append({"kid": kid, "private_key": private_key, "exp": exp})


def int_to_base64url(i: int) -> str:
    """Convert an integer to a Base64URL-encoded string."""
    length = (i.bit_length() + 7) // 8
    b = i.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Returns unexpired keys in JWKS format."""
    jwks_keys = []
    current_time = int(time.time())

    for key_data in keys:
        if key_data["exp"] > current_time:
            # Active key, add to JWKS
            private_key = key_data["private_key"]
            public_key = private_key.public_key()
            public_numbers = public_key.public_numbers()

            jwks_keys.append(
                {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": key_data["kid"],
                    "n": int_to_base64url(public_numbers.n),
                    "e": int_to_base64url(public_numbers.e),
                }
            )

    return jsonify({"keys": jwks_keys})


@app.route("/auth", methods=["POST"])
def auth():
    """Issues a signed JWT. Supports an ?expired=true parameter."""
    expired = request.args.get("expired", "false").lower() == "true"

    key_to_use = None
    current_time = int(time.time())

    for key_data in keys:
        is_expired = key_data["exp"] <= current_time
        if is_expired == expired:
            key_to_use = key_data
            break

    if not key_to_use:
        # Generate one on the fly if we don't have a matching one
        generate_key_pair(expired=expired)
        key_to_use = keys[-1]

    payload = {
        "exp": key_to_use["exp"],
        "iat": current_time,
        "iss": "jwks-server",
        "sub": "user123",
    }

    # Get private key in PEM format for PyJWT
    private_key_pem = key_to_use["private_key"].private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    encoded_jwt = jwt.encode(
        payload, private_key_pem, algorithm="RS256", headers={"kid": key_to_use["kid"]}
    )

    return encoded_jwt


# Generate an initial valid key pair
generate_key_pair()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
