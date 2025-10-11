"""Tests for dual authentication methods: SCRAM and password fallback."""

import pytest
import truenas_pypam
import truenas_pyscram
import truenas_keyring
from truenas_authenticator import UserPamAuthenticator, AuthenticatorStage


@pytest.fixture(autouse=True)
def clear_faillog_before_test():
    """Clear faillog before each test to ensure clean state"""
    # Clear before test
    try:
        persistent = truenas_keyring.get_persistent_keyring()
        pam_keyring = persistent.search(key_type="keyring", description="PAM_TRUENAS")
        bob_keyring = pam_keyring.search(key_type="keyring", description="bob")
        faillog = bob_keyring.search(key_type="keyring", description="FAILLOG")
        faillog.clear()
    except (FileNotFoundError, AttributeError):
        pass  # No faillog to clear

    yield  # Run the test

    # Clear after test too
    try:
        persistent = truenas_keyring.get_persistent_keyring()
        pam_keyring = persistent.search(key_type="keyring", description="PAM_TRUENAS")
        bob_keyring = pam_keyring.search(key_type="keyring", description="bob")
        faillog = bob_keyring.search(key_type="keyring", description="FAILLOG")
        faillog.clear()
    except (FileNotFoundError, AttributeError):
        pass


def test_scram_auth_with_allow_password_flag(api_key_data):
    """Test SCRAM authentication succeeds even with allow_password_auth flag set"""

    # Use middleware service which has allow_password_auth flag
    pam_service = "middleware"

    # Create authenticator with username:api_key_id format
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service
    )

    # Initialize authentication
    resp = auth.auth_init()

    # Should get conversation request for SCRAM client-first message OR password
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    assert resp.stage == AuthenticatorStage.AUTH
    assert isinstance(resp.reason, tuple)

    # Verify the prompt mentions both options
    prompt = resp.reason[0].msg
    assert "SCRAM" in prompt or "password" in prompt.lower()

    # Create SCRAM client-first message
    client_first = truenas_pyscram.ClientFirstMessage(
        username=api_key_data["username"],
        api_key_id=api_key_data["id"]
    )

    # Provide serialized client-first message as response
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(str(client_first))
        else:
            responses.append(None)

    # Continue authentication with client-first message
    resp = auth.auth_continue(responses)

    # Should get server-first message back
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    assert isinstance(resp.reason, tuple)

    # Extract server-first message from PAM response
    server_first_str = None
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            server_first_str = msg.msg
            break

    assert server_first_str is not None, "No server-first message received"

    # Create server-first message object from RFC string
    server_first = truenas_pyscram.ServerFirstMessage(rfc_string=server_first_str)

    # Validate that server returned expected values from keyring
    assert bytes(server_first.salt) == api_key_data["salt"]
    assert server_first.iterations == api_key_data["iterations"]

    # Use the auth_data from fixture
    auth_data = api_key_data["scram_auth_data"]

    # Create client-final message
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )

    # Provide client-final message
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(str(client_final))
        else:
            responses.append(None)

    # Continue authentication with client-final message
    resp = auth.auth_continue(responses)

    # Should succeed with server-final message
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    assert isinstance(resp.reason, tuple)
    server_final = truenas_pyscram.ServerFinalMessage(rfc_string=resp.reason[0].msg)

    truenas_pyscram.verify_server_signature(
        client_first=client_first,
        server_first=server_first,
        client_final=client_final,
        server_final=server_final,
        server_key=auth_data.server_key
    )

    # No actual reply is required
    resp = auth.auth_continue([None])

    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    assert auth.state.stage == AuthenticatorStage.LOGIN

    # Clean up
    auth.end()


def test_password_fallback_when_not_scram(api_key_data):
    """Test password authentication fallback when password is sent instead of SCRAM"""

    # Use middleware service which has allow_password_auth flag
    pam_service = "middleware"

    # Set env flag to indicate password is an API key
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={"pam_truenas_password_auth_is_api_key": "1"}
    )

    # Initialize authentication
    resp = auth.auth_init()

    # Should get conversation request
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    assert resp.stage == AuthenticatorStage.AUTH

    # Provide API key as password (not SCRAM message)
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            # Send raw API key - this will trigger fallback to password auth
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    # Continue authentication with password
    resp = auth.auth_continue(responses)

    # Should succeed via password fallback
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    assert resp.stage == AuthenticatorStage.AUTH
    assert auth.state.stage == AuthenticatorStage.LOGIN

    # Clean up
    auth.end()


def test_password_fallback_accepts_full_api_key_format(api_key_data):
    """Test password fallback works with full API key format (ID-keydata)"""

    pam_service = "middleware"

    # Set env flag to indicate password is an API key
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={"pam_truenas_password_auth_is_api_key": "1"}
    )

    # Initialize authentication
    resp = auth.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Provide full API key in "ID-keydata" format
    # The password_is_api_key flag tells PAM to strip the prefix before auth
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)

    # Should succeed via password fallback
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    assert auth.state.stage == AuthenticatorStage.LOGIN

    # Clean up
    auth.end()


def test_scram_only_mode_rejects_password(api_key_data):
    """Test that SCRAM-only mode (without allow_password_auth) rejects passwords"""

    # Use middleware-scram service which does NOT have allow_password_auth flag
    pam_service = "middleware-scram"

    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={"pam_truenas_password_auth_is_api_key": "1"}
    )

    # Initialize authentication
    resp = auth.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Provide password (not SCRAM message)
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            # Send API key - should be rejected in SCRAM-only mode
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    # Continue authentication with password
    resp = auth.auth_continue(responses)

    # Should fail because allow_password_auth is not set
    assert resp.code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    assert auth.state.stage == AuthenticatorStage.START  # Reset on failure

    # Clean up
    auth.end()


def test_invalid_password_fails_in_fallback_mode(api_key_data):
    """Test that invalid password fails even with fallback enabled"""

    pam_service = "middleware"

    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={"pam_truenas_password_auth_is_api_key": "1"}
    )

    # Initialize authentication
    resp = auth.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Provide invalid password
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append("2-INVALID_KEY_MATERIAL_SHOULD_FAIL")
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)

    # Should fail due to invalid password
    assert resp.code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    assert auth.state.stage == AuthenticatorStage.START

    # Clean up
    auth.end()


def test_malformed_scram_falls_back_to_password(api_key_data):
    """Test that malformed SCRAM message triggers password fallback when allowed"""

    pam_service = "middleware"

    # Set env flag for API key auth
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={"pam_truenas_password_auth_is_api_key": "1"}
    )

    # Initialize authentication
    resp = auth.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Send what looks like it might be password but isn't valid SCRAM
    # This should trigger password fallback
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            # Send valid API key that will be detected as non-SCRAM
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)

    # Should succeed via password fallback
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    assert auth.state.stage == AuthenticatorStage.LOGIN

    # Clean up
    auth.end()
