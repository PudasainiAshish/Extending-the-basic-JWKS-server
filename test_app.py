"""
Test suite for the Flask app and RSA key utilities.
"""
import time
from app import app
import jwt  
import pytest
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import mock
import sqlite3


@pytest.fixture
def client():
    """Pytest fixture to create a test client for the Flask app."""
    with app.test_client() as client:
        yield client

def test_jwks(client):
    """Test the JWKS endpoint to ensure keys are returned."""
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    keys = response.get_json()['keys']
    assert len(keys) > 0  # Ensuring at least one key is returned

def test_auth(client):
    """Test the /auth endpoint to ensure JWT is returned."""
    response = client.post('/auth')
    assert response.status_code == 200
    token = response.get_json()['token']

    # Verifying the token's header and content
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header['kid']

    active_key = get_active_key(kid)
    assert active_key is not None

def test_expired_auth(client):
    """Test expired token generation and validation."""
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    token = response.get_json()['token']

    with mock.patch('jwt.api_jws.PyJWS._verify_signature', return_value=True):
        decoded = jwt.decode(token, algorithms=['RS256'], options={"verify_exp": False})

    assert decoded.get('exp', None) <= int(time.time())

def get_active_key(kid):
    DB_PATH = "totally_not_my_privateKeys.db"
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT "key" FROM keys WHERE kid = ?', (kid,))
    key = cursor.fetchone()
    conn.close()
    return key
