"""Tests for API key authentication using PAM module."""

import pytest
import truenas_pypam
from truenas_authenticator import UserPamAuthenticator, AuthenticatorStage


def test_api_key_authentication(api_key_data, pam_service):
    """Test basic API key authentication using PAM module"""

    # Create authenticator with the middleware PAM service
    # Username format for API key auth is "username:api_key_id"
    # Set env variable to tell PAM the password is an API key
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={"pam_truenas_password_auth_is_api_key": "1"}
    )

    # Initialize authentication
    resp = auth.auth_init()

    # Should get conversation request for password
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    assert resp.stage == AuthenticatorStage.AUTH
    assert isinstance(resp.reason, tuple)

    # Provide API key as password response
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    # Continue authentication with API key
    resp = auth.auth_continue(responses)

    # Should succeed
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    assert resp.stage == AuthenticatorStage.AUTH
    assert auth.state.stage == AuthenticatorStage.LOGIN

    # Clean up
    auth.end()


def test_api_key_authentication_invalid_key(api_key_data, pam_service):
    """Test authentication fails with invalid API key"""

    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={"pam_truenas_password_auth_is_api_key": "1"}
    )

    # Initialize authentication
    resp = auth.auth_init()

    # Should get conversation request
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Provide invalid API key
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append("2-INVALID_KEY_DATA_THAT_SHOULD_FAIL")
        else:
            responses.append(None)

    # Continue authentication with invalid key
    resp = auth.auth_continue(responses)

    # Should fail
    assert resp.code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    assert auth.state.stage == AuthenticatorStage.START  # Reset on failure

    # Clean up
    auth.end()


def test_api_key_authentication_wrong_user(api_key_data, pam_service):
    """Test authentication fails when using API key with wrong username"""

    # Try to use API key ID 2 with alice (but key is registered for bob)
    auth = UserPamAuthenticator(
        username=f"alice:{api_key_data['id']}",  # Wrong username for this API key
        service=pam_service,
        pam_env={"pam_truenas_password_auth_is_api_key": "1"}
    )

    # Initialize authentication
    resp = auth.auth_init()

    # Should fail immediately with PAM_AUTHINFO_UNAVAIL because
    # the API key doesn't exist for user "alice" in the keyring
    assert resp.code == truenas_pypam.PAMCode.PAM_AUTHINFO_UNAVAIL
    assert resp.stage == AuthenticatorStage.AUTH
    assert "pam_authenticate() failed" in resp.reason

    # Clean up
    auth.end()


def test_api_key_authentication_raw_key_with_id_in_username(api_key_data, pam_service):
    """Test that raw key without ID prefix works when ID is in username"""

    # When username contains API key ID, PAM accepts raw key data
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={"pam_truenas_password_auth_is_api_key": "1"}
    )

    # Initialize authentication
    resp = auth.auth_init()

    # Should get conversation request
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Provide raw API key without ID prefix (ID is already in username)
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            # Raw key data without the "2-" prefix
            responses.append("DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC")
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)

    # Should succeed because API key ID is in the username
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    assert auth.state.stage == AuthenticatorStage.LOGIN

    # Clean up
    auth.end()


def test_api_key_authentication_with_env_flag(api_key_data, pam_service):
    """Test API key auth with env flag - still requires ID in username"""

    # API key ID must ALWAYS be in username, env flag only affects password parsing
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",  # ID always required
        service=pam_service,
        pam_env={"pam_truenas_password_auth_is_api_key": "1"}
    )

    # Initialize authentication
    resp = auth.auth_init()

    # Should get conversation request
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # With env flag, we can provide raw key without ID prefix
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            # Raw key data without the "2-" prefix (env flag tells PAM it's an API key)
            responses.append("DJpfT7q7dHu6RRfeMwP8aJlGeUOmRWbDKnnzxnsc8F1YAsDNbl8aDM4X1cYwPmcC")
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)

    # Should succeed
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    assert auth.state.stage == AuthenticatorStage.LOGIN

    # Clean up
    auth.end()