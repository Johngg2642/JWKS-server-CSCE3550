"""Mock authentication and JWKS endpoints backed by persistent SQLite keys."""

import base64
import time
from contextlib import closing

import jwt
from cryptography.hazmat.primitives import serialization
from flask import Flask, Response, jsonify, request

from storage import (
    DATABASE_NAME,
    connect,
    generate_key_pair,
    initialize_database,
    select_key,
)


def int_to_base64url(value: int) -> str:
    """Encode an RSA public integer as unpadded Base64URL."""
    data = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def create_app(database=DATABASE_NAME):
    """Create the service using a database in the current working directory."""
    app = Flask(__name__)
    app.config["DATABASE"] = str(database)
    initialize_database(app.config["DATABASE"])

    @app.get("/.well-known/jwks.json")
    def jwks():
        """Publish every unexpired key's public components, never private PEM."""
        with closing(connect(app.config["DATABASE"])) as connection:
            rows = connection.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid",
                (int(time.time()),),
            ).fetchall()
        public_keys = []
        for row in rows:
            private_key = serialization.load_pem_private_key(row["key"], password=None)
            numbers = private_key.public_key().public_numbers()
            public_keys.append(
                {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(row["kid"]),
                    "n": int_to_base64url(numbers.n),
                    "e": int_to_base64url(numbers.e),
                }
            )
        return jsonify({"keys": public_keys})

    @app.post("/auth")
    def auth():
        """Mock Basic/JSON authentication and sign with a key read from SQLite."""
        expired = "expired" in request.args
        now = int(time.time())
        with closing(connect(app.config["DATABASE"])) as connection, connection:
            # Serialize selection/renewal so concurrent requests share a new key.
            connection.execute("BEGIN IMMEDIATE")
            row = select_key(connection, expired, now)
            if row is None:
                kid = generate_key_pair(connection, expired)
                row = connection.execute(
                    "SELECT kid, key, exp FROM keys WHERE kid = ?", (kid,)
                ).fetchone()
        username = "user123"
        if request.authorization and request.authorization.type == "basic":
            username = request.authorization.username or username
        elif request.is_json:
            body = request.get_json(silent=True)
            if isinstance(body, dict) and isinstance(body.get("username"), str):
                username = body["username"] or username
        private_key = serialization.load_pem_private_key(row["key"], password=None)
        token = jwt.encode(
            {"exp": row["exp"], "iat": now, "iss": "jwks-server", "sub": username},
            private_key,
            algorithm="RS256",
            headers={"kid": str(row["kid"])},
        )
        return Response(token, mimetype="text/plain")

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
