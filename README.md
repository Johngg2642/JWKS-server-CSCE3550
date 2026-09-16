# JWKS & Authentication Server

A lightweight, RFC 7517 compliant RESTful JSON Web Key Set (JWKS) and mock authentication server written in Python using Flask.

## Features
- Generates 2048-bit RSA key pairs with expiration
- Exposes unexpired public keys at `/.well-known/jwks.json`
- Issues signed JWTs at `/auth`
- Can issue JWTs signed with expired keys using `?expired=true`

## Prerequisites
- Python 3.10+

## Setup & Execution

1. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the server:
   ```bash
   python app.py
   ```
   The server will start on `http://0.0.0.0:8080`.

## Endpoints

### `GET /.well-known/jwks.json`
Returns a JWKS containing all currently active (unexpired) public keys.

### `POST /auth`
Returns a signed JWT.
- Query Parameter: `?expired=true` (optional). If true, the token will be signed with an expired key and will have a past `exp` timestamp.

## Testing & Coverage

To run the test suite and see coverage information:
```bash
pytest tests/ --cov=app --cov-report=term-missing
```
