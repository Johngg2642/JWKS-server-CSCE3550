"""SQLite persistence for RSA signing keys; all values use bound parameters."""

import sqlite3
import time
from contextlib import closing

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DATABASE_NAME = "totally_not_my_privateKeys.db"


def connect(database):
    """Open a connection with named columns."""
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    return connection


def generate_key_pair(connection, expired=False):
    """Persist a PKCS1 PEM private key as a BLOB and return its database ID."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    expiration = int(time.time()) + (-3600 if expired else 3600)
    cursor = connection.execute(
        "INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, expiration)
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


def initialize_database(database):
    """Create the required schema and seed missing key categories on startup."""
    with closing(connect(database)) as connection, connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS keys("
            "kid INTEGER PRIMARY KEY AUTOINCREMENT, "
            "key BLOB NOT NULL, exp INTEGER NOT NULL)"
        )
        now = int(time.time())
        for expired in (False, True):
            if select_key(connection, expired, now) is None:
                generate_key_pair(connection, expired)
