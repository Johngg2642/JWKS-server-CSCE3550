"""SQLite persistence for encrypted signing keys, users, and auth logs."""

import base64
import os
import sqlite3
import time
from contextlib import closing

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATABASE_NAME = "totally_not_my_privateKeys.db"
KEY_FORMAT = b"jwks:aes-gcm:v1:"
NONCE_SIZE = 12


def load_key_cipher():
    """Load a Base64-encoded AES-256 key from the environment."""
    error = "NOT_MY_KEY must contain 32 random bytes encoded as Base64"
    try:
        key = base64.b64decode(os.environ.get("NOT_MY_KEY", ""), validate=True)
    except ValueError:
        raise ValueError(error) from None
    if len(key) != 32:
        raise ValueError(error)
    return AESGCM(key)


def encrypt_key(pem, cipher):
    """Store the format marker and random nonce alongside the ciphertext and tag."""
    nonce = os.urandom(NONCE_SIZE)
    return KEY_FORMAT + nonce + cipher.encrypt(nonce, pem, KEY_FORMAT)


def decrypt_key(blob, cipher):
    """Authenticate the stored ciphertext before returning its private PEM."""
    if not blob.startswith(KEY_FORMAT):
        raise ValueError("Unrecognized stored signing key format")
    payload = blob[len(KEY_FORMAT) :]
    try:
        return cipher.decrypt(payload[:NONCE_SIZE], payload[NONCE_SIZE:], KEY_FORMAT)
    except (InvalidTag, ValueError):
        raise ValueError(
            "Unable to decrypt stored signing keys with NOT_MY_KEY"
        ) from None


def connect(database):
    """Open a connection with named columns."""
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def generate_key_pair(connection, cipher, expired=False):
    """Persist an encrypted PKCS1 private key and return its database ID."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    expiration = int(time.time()) + (-3600 if expired else 3600)
    cursor = connection.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)",
        (encrypt_key(pem, cipher), expiration),
    )
    return cursor.lastrowid


def select_key(connection, expired, now):
    """Choose the longest-lived active key, or most recently expired key."""
    if expired:
        return connection.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC, kid DESC LIMIT 1",
            (now,),
        ).fetchone()
    return connection.execute(
        "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC, kid DESC LIMIT 1",
        (now,),
    ).fetchone()


def initialize_database(database, cipher):
    """Create tables, migrate Project 2 keys, and seed missing key categories."""
    with closing(connect(database)) as connection, connection:
        connection.execute("PRAGMA secure_delete = ON")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS keys("
            "kid INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key BLOB NOT NULL, exp INTEGER NOT NULL)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        for row in connection.execute("SELECT kid, key FROM keys").fetchall():
            blob = row["key"]
            if blob.startswith(b"-----BEGIN RSA PRIVATE KEY-----"):
                connection.execute(
                    "UPDATE keys SET key = ? WHERE kid = ?",
                    (encrypt_key(blob, cipher), row["kid"]),
                )
            else:
                decrypt_key(blob, cipher)
        now = int(time.time())
        for expired in (False, True):
            if select_key(connection, expired, now) is None:
                generate_key_pair(connection, cipher, expired)
