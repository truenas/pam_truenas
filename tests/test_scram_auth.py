"""Tests for SCRAM authentication using PAM module."""

import pytest
import truenas_pypam
import truenas_pyscram
from truenas_authenticator import UserPamAuthenticator, AuthenticatorStage


def test_scram_authentication(api_key_data):
    """Test SCRAM authentication challenge/response with API key"""

    # Use middleware-scram service for SCRAM auth (no do_password_auth flag)
    pam_service = "middleware-scram"

    # Create authenticator with username:api_key_id format
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service
    )

    # Initialize authentication
    resp = auth.auth_init()

    # Should get conversation request for SCRAM client-first message
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    assert resp.stage == AuthenticatorStage.AUTH
    assert isinstance(resp.reason, tuple)

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
    assert bytes(server_first.salt) == api_key_data["salt"], f"Unexpected salt: got {bytes(server_first.salt)}, expected {api_key_data['salt']}"
    assert server_first.iterations == api_key_data["iterations"], f"Unexpected iterations: got {server_first.iterations}, expected {api_key_data['iterations']}"

    # Use the auth_data from fixture (already generated in conftest)
    auth_data = api_key_data["scram_auth_data"]

    # Create client-final message
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )

    # Verify the client-final message is correct before sending to PAM
    truenas_pyscram.verify_client_final_message(
        client_first=client_first,
        server_first=server_first,
        client_final=client_final,
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


def test_scram_authentication_invalid_password(api_key_data):
    """Test SCRAM authentication fails with wrong password"""

    pam_service = "middleware-scram"

    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service
    )

    # Initialize authentication
    resp = auth.auth_init()

    # Should get conversation request
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Create SCRAM client-first message
    client_first = truenas_pyscram.ClientFirstMessage(
        username=api_key_data["username"],
        api_key_id=api_key_data["id"]
    )

    # Provide client-first message
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(str(client_first))
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)

    # Should get server-first message
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Extract server-first message
    server_first_str = None
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            server_first_str = msg.msg
            break

    assert server_first_str is not None

    # Create server-first message object from RFC string
    server_first = truenas_pyscram.ServerFirstMessage(rfc_string=server_first_str)

    # Validate server returned expected values
    assert bytes(server_first.salt) == api_key_data["salt"], f"Unexpected salt: got {bytes(server_first.salt)}, expected {api_key_data['salt']}"
    assert server_first.iterations == api_key_data["iterations"], f"Unexpected iterations: got {server_first.iterations}, expected {api_key_data['iterations']}"

    # Generate auth data with WRONG (random) salted password
    # Omitting salted_password will generate a random one
    wrong_auth_data = truenas_pyscram.generate_scram_auth_data(
        salt=server_first.salt,
        iterations=server_first.iterations
    )

    # Create client-final message with wrong auth data
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=wrong_auth_data.client_key,
        stored_key=wrong_auth_data.stored_key
    )

    # Provide client-final message
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(str(client_final))
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)

    # Should fail authentication
    assert resp.code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    assert auth.state.stage == AuthenticatorStage.START  # Reset on failure

    # Clean up
    auth.end()


def test_scram_authentication_wrong_user(api_key_data):
    """Test SCRAM authentication fails when API key doesn't exist for user"""

    pam_service = "middleware-scram"

    # Try to use API key ID 2 with alice (but key is registered for bob)
    auth = UserPamAuthenticator(
        username=f"alice:{api_key_data['id']}",
        service=pam_service
    )

    # Initialize authentication
    resp = auth.auth_init()

    # Should fail immediately because API key doesn't exist for alice
    assert resp.code == truenas_pypam.PAMCode.PAM_AUTHINFO_UNAVAIL
    assert resp.stage == AuthenticatorStage.AUTH
    assert "pam_authenticate() failed" in resp.reason

    # Clean up
    auth.end()


def test_scram_authentication_malformed_client_first(api_key_data):
    """Test SCRAM authentication fails with malformed client-first message"""

    pam_service = "middleware-scram"

    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service
    )

    # Initialize authentication
    resp = auth.auth_init()

    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Send malformed client-first message
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append("invalid-client-first-message")
        else:
            responses.append(None)

    # Continue authentication with malformed message
    resp = auth.auth_continue(responses)

    # Should fail authentication due to parse error
    assert resp.code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    assert auth.state.stage == AuthenticatorStage.START

    # Clean up
    auth.end()


def test_scram_authentication_api_key_without_id_prefix(api_key_data):
    """Test that SCRAM always uses raw key material regardless of how it's provided"""

    pam_service = "middleware-scram"

    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service
    )

    # Initialize authentication
    resp = auth.auth_init()

    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Create client-first message
    client_first = truenas_pyscram.ClientFirstMessage(
        username=api_key_data["username"],
        api_key_id=api_key_data["id"]
    )

    # Provide client-first message
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(str(client_first))
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)

    # Should get server-first message
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    # Extract and parse server-first message
    server_first_str = None
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            server_first_str = msg.msg
            break

    assert server_first_str is not None

    # Create server-first message object from RFC string
    server_first = truenas_pyscram.ServerFirstMessage(rfc_string=server_first_str)

    # Validate server returned expected values
    assert bytes(server_first.salt) == api_key_data["salt"], f"Unexpected salt: got {bytes(server_first.salt)}, expected {api_key_data['salt']}"
    assert server_first.iterations == api_key_data["iterations"], f"Unexpected iterations: got {server_first.iterations}, expected {api_key_data['iterations']}"

    # Use the auth_data from fixture (already generated in conftest)
    # IMPORTANT: In SCRAM, the ID is communicated separately, not in the password
    auth_data = api_key_data["scram_auth_data"]

    # Create client-final message
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )

    # Verify the client-final message is correct before sending to PAM
    truenas_pyscram.verify_client_final_message(
        client_first=client_first,
        server_first=server_first,
        client_final=client_final,
        stored_key=auth_data.stored_key
    )

    # Provide client-final message
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(str(client_final))
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)

    # Should get server-final message
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    assert isinstance(resp.reason, tuple)
    server_final = truenas_pyscram.ServerFinalMessage(rfc_string=resp.reason[0].msg)

    # Verify server signature
    truenas_pyscram.verify_server_signature(
        client_first=client_first,
        server_first=server_first,
        client_final=client_final,
        server_final=server_final,
        server_key=auth_data.server_key
    )

    # No actual reply is required
    resp = auth.auth_continue([None])

    # Should succeed
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    assert auth.state.stage == AuthenticatorStage.LOGIN

    # Clean up
    auth.end()
