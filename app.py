"""
Flask application to serve JWKS and handle authentication using SQlite.

Provides a simple JWT authentication server along with a JWKS endpoint.
Keys are stored in an SQLite database and used to sign JWT tokens. Both valid and expired
keys are managed, and the script handles requests for issuing JWTs and retrieving valid keys
for JSON Web Key Sets (JWKS). 

"""

from flask import Flask, jsonify, request
import jwt  # PyJWT
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import re
import time
import sqlite3

app = Flask(__name__)

DB_PATH = "totally_not_my_privateKeys.db"

def create_database():
    """Create the database and the keys table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS keys (
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )''')
    conn.commit()
    conn.close()

def generate_rsa_key(expired=False):
    """
    Generate an RSA key and store it in the database.

    Setting up RSA key generation and handling expiration for both valid
    and expired keys, where expiration is controlled based on the flag.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Setting expiry time based on whether the key should be expired
    expiry = int(time.time()) + 3600 if not expired else int(time.time()) - 1

    # Storing the key in the SQLite database using parameterized insertion
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    test_query = 'INSERT INTO keys (key, exp) VALUES (?, ?)'
    c.execute(test_query, (key_pem, expiry))
    conn.commit()
    conn.close()

create_database()
generate_rsa_key(expired=True)
generate_rsa_key(expired=False)


def int_to_base64url(n):
    """
    Convert integer to base64 URL encoding.

    This handles the conversion of RSA components to base64url format
    as required for the JWKS output.
    """
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')).rstrip(b'=').decode('utf-8')

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """
    Serve JWKS (JSON Web Key Set).

    This endpoint provides public keys that are used to verify JWTs. Only non-expired
    keys are included in the response.
    """
    jwk_keys = []
    current_time = int(time.time())

    # Query to retrieve valid (non-expired) keys from the database
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT kid, key, exp FROM keys WHERE exp > ?', (current_time,))
    key_rows = c.fetchall()
    conn.close()

    for kid, key_pem, exp in key_rows:
        key = serialization.load_pem_private_key(
            key_pem,
            password=None,
        )
        public_key = key.public_key()

        public_numbers = public_key.public_numbers()
        jwk = {
            "kty": "RSA",
            "kid": str(kid),
            "use": "sig",
            "n": int_to_base64url(public_numbers.n),
            "e": int_to_base64url(public_numbers.e),
            "alg": "RS256"
        }
        jwk_keys.append(jwk)

    return jsonify({"keys": jwk_keys})


@app.route('/auth', methods=['POST'])
def auth():
    """
    Handle authentication and issue JWT.

    This endpoint signs a JWT with either a valid or expired RSA key based
    on the 'expired' flag provided in the request.
    """
    expired = request.args.get('expired') == 'true'
    current_time = int(time.time())

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    if expired:
        # Selecting an expired key
        c.execute('SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1', (current_time,))
    else:
        # Selecting a valid key
        c.execute('SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp LIMIT 1', (current_time,))

    key_row = c.fetchone()
    conn.close()

    if key_row:
        kid, key_pem, exp = key_row
        key = serialization.load_pem_private_key(
            key_pem,
            password=None,
        )

        # Setting expiration time for the token
        exp_time = datetime.utcnow() + timedelta(minutes=10) if not expired else datetime.utcnow() - timedelta(
            minutes=10)

        token = jwt.encode(
            {
                "sub": "userABC",
                "exp": exp_time,
                "iat": datetime.utcnow(),
                "iss": "auth_server",
            },
            key,
            algorithm="RS256",
            headers={"kid": str(kid)}
        )

        return jsonify({"token": token})
    else:
        return jsonify({"error": "No valid key found"}), 404


if __name__ == '__main__':
    app.run(port=8080)
