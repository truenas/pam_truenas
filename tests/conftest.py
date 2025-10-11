import pytest
from base64 import b64encode, b64decode
import truenas_api_key
import truenas_pypwenc
import truenas_pyscram


def pytest_sessionstart(session):
    """Setup API key in keyring at the start of the test session"""
    try:
        # Test API key data based on commit_keyring_change.py
        api_key_data = {
            "id": 2,
            "name": "test",
            "username": "bob",
            "salt": b'KCwXnX9l35e0ndOu',
            "salted_password_b64": 'sljMczeiN9kEqyOIrjoQ1QiBhnrmL++DtRdeyv+DHmQkkzoypbkzHIVA1iM/NVviC50dVpDKKlD3L2pv9KDdfw==',
            "iterations": 500000,
            "raw_key": "2-DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC",
        }

        # Generate SCRAM auth data
        salted_password = truenas_pyscram.CryptoDatum(
            b64decode(api_key_data["salted_password_b64"])
        )

        auth_data = truenas_pyscram.generate_scram_auth_data(
            salted_password=salted_password,
            salt=truenas_pyscram.CryptoDatum(api_key_data["salt"]),
            iterations=api_key_data["iterations"]
        )

        # Store auth_data in session for fixtures to use
        session.scram_auth_data = auth_data
        session.api_key_salt = api_key_data["salt"]
        session.api_key_iterations = api_key_data["iterations"]

        # Create UserApiKey entry
        entry = truenas_api_key.UserApiKey(
            api_key_data["username"],
            api_key_data["id"],
            'sha512',
            api_key_data["iterations"],
            0,  # expiry (0 = no expiry)
            b64encode(api_key_data["salt"]).decode(),
            b64encode(bytes(auth_data.server_key)).decode(),
            b64encode(bytes(auth_data.stored_key)).decode()
        )

        # Get encryption context (create secret if it doesn't exist)
        ctx = truenas_pypwenc.get_context(create=True)

        def encrypt(b):
            return ctx.encrypt(b.encode()).decode()

        # Commit to keyring
        truenas_api_key.keyring.commit_user_entry(
            api_key_data["username"],
            [entry],
            encrypt
        )

        print(f"Successfully set up API key for user '{api_key_data['username']}' with ID {api_key_data['id']}")

    except Exception as e:
        pytest.exit(f"Failed to set up API key in keyring: {e}", returncode=1)


@pytest.fixture
def api_key_data(request):
    """Fixture providing test API key data including SCRAM auth data"""
    return {
        "id": 2,
        "username": "bob",
        "raw_key": "2-DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC",
        "salt": request.session.api_key_salt,
        "iterations": request.session.api_key_iterations,
        "scram_auth_data": request.session.scram_auth_data,
    }


@pytest.fixture
def pam_service():
    """Fixture providing the PAM service name for testing"""
    return "middleware"  # Using the middleware PAM service as specified