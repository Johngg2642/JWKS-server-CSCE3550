"""JWKS, user registration, and logged mock authentication endpoints."""

import base64
import time
from collections import deque
from contextlib import closing
from threading import Lock
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from flask import Flask, Response, jsonify, request

from storage import (
    DATABASE_NAME,
    connect,
    decrypt_key,
    generate_key_pair,
    initialize_database,
    load_key_cipher,
    select_key,
)

AUTH_REQUESTS_PER_SECOND = 10


def int_to_base64url(value: int) -> str:
    """Encode an RSA public integer as unpadded Base64URL."""
    data = value.to_bytes((value.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def create_app(database=DATABASE_NAME):
    """Create the service using a database in the current working directory."""
    app = Flask(__name__)
    app.config["DATABASE"] = str(database)
    cipher = load_key_cipher()
    initialize_database(app.config["DATABASE"], cipher)
    password_hasher = PasswordHasher(
        time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16
    )
    auth_requests = deque()
    auth_lock = Lock()

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
            private_key = serialization.load_pem_private_key(
                decrypt_key(row["key"], cipher), password=None
            )
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

    @app.post("/register")
    def register():
        """Issue a UUIDv4 password and persist only its salted Argon2id hash."""
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return jsonify(error="Expected a JSON object"), 400

        username, email = body.get("username"), body.get("email")
        if not all(
            isinstance(value, str) and 0 < len(value) <= 254 and value.strip()
            for value in (username, email)
        ):
            return jsonify(error="Username and email are required"), 400

        password = str(uuid4())
        password_hash = password_hasher.hash(password)
        with closing(connect(app.config["DATABASE"])) as connection, connection:
            result = connection.execute(
                """
                INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)
                ON CONFLICT DO NOTHING
                """,
                (username, password_hash, email),
            )
        if result.rowcount == 0:
            return jsonify(error="Username or email already exists"), 409

        response = jsonify(password=password)
        response.headers["Cache-Control"] = "no-store"
        return response, 201

    @app.post("/auth")
    def auth():
        """Rate-limit, sign, and log mock authentication requests."""
        with auth_lock:
            arrival = time.monotonic()
            while auth_requests and auth_requests[0] <= arrival - 1:
                auth_requests.popleft()
            if len(auth_requests) >= AUTH_REQUESTS_PER_SECOND:
                return (
                    jsonify(error="Too many authentication requests"),
                    429,
                    {"Retry-After": "1"},
                )
            auth_requests.append(arrival)

        expired = "expired" in request.args
        now = int(time.time())
        username = "user123"
        if request.authorization and request.authorization.type == "basic":
            username = request.authorization.username or username
        elif request.is_json:
            body = request.get_json(silent=True)
            if isinstance(body, dict) and isinstance(body.get("username"), str):
                username = body["username"] or username
        with closing(connect(app.config["DATABASE"])) as connection, connection:
            # Serialize selection/renewal so concurrent requests share a new key.
            connection.execute("BEGIN IMMEDIATE")
            row = select_key(connection, expired, now)
            if row is None:
                kid = generate_key_pair(connection, cipher, expired)
                row = connection.execute(
                    "SELECT kid, key, exp FROM keys WHERE kid = ?", (kid,)
                ).fetchone()
            private_key = serialization.load_pem_private_key(
                decrypt_key(row["key"], cipher), password=None
            )
            token = jwt.encode(
                {"exp": row["exp"], "iat": now, "iss": "jwks-server", "sub": username},
                private_key,
                algorithm="RS256",
                headers={"kid": str(row["kid"])},
            )
            connection.execute(
                """
                INSERT INTO auth_logs (request_ip, request_timestamp, user_id)
                VALUES (?, datetime(?, 'unixepoch'),
                        (SELECT id FROM users WHERE username = ?))
                """,
                (request.remote_addr, now, username),
            )
        return Response(token, mimetype="text/plain")

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=8080)
