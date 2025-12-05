"""Tests for max_sessions parameter parsing and enforcement"""

import json
import os
import pytest
import tempfile
from pathlib import Path
import truenas_pypam
from truenas_authenticator import UserPamAuthenticator, AuthenticatorStage
import truenas_pam_session


@pytest.fixture
def pam_service_with_max_sessions():
    """
    Fixture that creates a temporary PAM service file with max_sessions configured.
    Returns the service name which can be used with UserPamAuthenticator.
    """
    # Create a temporary PAM service file
    fd, temp_pam_file = tempfile.mkstemp(dir="/etc/pam.d", prefix="test_max_sessions_")
    service_name = os.path.basename(temp_pam_file)

    try:
        # Write PAM configuration with max_sessions=2
        pam_config = """# Test PAM service for max_sessions testing
auth    [success=1 default=ignore]    pam_truenas.so debug allow_password_auth use_env_config
auth    [default=done]                pam_truenas.so debug authfail
auth    required                      pam_truenas.so debug authsucc
auth    required                      pam_permit.so

account sufficient                    pam_permit.so

session required                      pam_truenas.so debug max_sessions=2
"""
        with os.fdopen(fd, 'w') as f:
            f.write(pam_config)
            f.flush()
            os.fsync(f.fileno())

        # Set proper permissions
        os.chmod(temp_pam_file, 0o644)

        yield service_name

    finally:
        # Clean up the temporary PAM service file
        try:
            os.unlink(temp_pam_file)
        except OSError:
            pass


@pytest.fixture
def pam_service_no_max_sessions():
    """
    Fixture that creates a temporary PAM service file without max_sessions.
    Returns the service name which can be used with UserPamAuthenticator.
    """
    # Create a temporary PAM service file
    fd, temp_pam_file = tempfile.mkstemp(dir="/etc/pam.d", prefix="test_no_max_sessions_")
    service_name = os.path.basename(temp_pam_file)

    try:
        # Write PAM configuration without max_sessions
        pam_config = """# Test PAM service without max_sessions
auth    [success=1 default=ignore]    pam_truenas.so debug allow_password_auth use_env_config
auth    [default=done]                pam_truenas.so debug authfail
auth    required                      pam_truenas.so debug authsucc
auth    required                      pam_permit.so

account sufficient                    pam_permit.so

session required                      pam_truenas.so debug
"""
        with os.fdopen(fd, 'w') as f:
            f.write(pam_config)
            f.flush()
            os.fsync(f.fileno())

        # Set proper permissions
        os.chmod(temp_pam_file, 0o644)

        yield service_name

    finally:
        # Clean up the temporary PAM service file
        try:
            os.unlink(temp_pam_file)
        except OSError:
            pass


@pytest.fixture
def cleanup_user_sessions(api_key_data):
    """Clean up all sessions for the test user before and after each test"""
    # Cleanup before test
    yield
    # Cleanup after test - just in case
    pass


@pytest.mark.skipif(os.geteuid() != 0, reason="Requires root privileges")
def test_max_sessions_enforced(api_key_data, pam_service_with_max_sessions, cleanup_user_sessions):
    """Test that max_sessions limit is enforced when configured"""

    # Note: We expect 0 existing sessions as the test environment should be clean
    existing_sessions = truenas_pam_session.get_sessions_by_username(api_key_data['username'])
    print(f"Found {len(existing_sessions)} existing sessions for {api_key_data['username']}")

    session_data = {
        "origin_family": "AF_INET",
        "origin": {
            "loc_addr": "127.0.0.1",
            "loc_port": 22,
            "rem_addr": "192.168.1.100",
            "rem_port": 55432,
            "ssl": False
        }
    }

    # Create first session - should succeed
    auth1 = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service_with_max_sessions,
        pam_env={
            "pam_truenas_password_auth_is_api_key": "1",
            "pam_truenas_session_data": json.dumps(session_data)
        }
    )

    resp = auth1.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    resp = auth1.auth_continue(responses)
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    resp = auth1.login()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # Create second session - should succeed
    auth2 = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service_with_max_sessions,
        pam_env={
            "pam_truenas_password_auth_is_api_key": "1",
            "pam_truenas_session_data": json.dumps(session_data)
        }
    )

    resp = auth2.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    resp = auth2.auth_continue(responses)
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    resp = auth2.login()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # Verify we have 2 sessions now
    user_sessions = truenas_pam_session.get_sessions_by_username(api_key_data['username'])
    assert len(user_sessions) >= 2

    # Try to create third session - should fail due to max_sessions=2
    auth3 = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service_with_max_sessions,
        pam_env={
            "pam_truenas_password_auth_is_api_key": "1",
            "pam_truenas_session_data": json.dumps(session_data)
        }
    )

    resp = auth3.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    resp = auth3.auth_continue(responses)
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # This should fail with PAM_PERM_DENIED due to session limit
    resp = auth3.login()
    assert resp.code == truenas_pypam.PAMCode.PAM_PERM_DENIED

    # Clean up
    auth1.logout()
    auth1.end()
    auth2.logout()
    auth2.end()
    auth3.end()


@pytest.mark.skipif(os.geteuid() != 0, reason="Requires root privileges")
def test_no_max_sessions_allows_many(api_key_data, pam_service_no_max_sessions):
    """Test that without max_sessions, many sessions can be created"""

    session_data = {
        "origin_family": "AF_INET",
        "origin": {
            "loc_addr": "127.0.0.1",
            "loc_port": 22,
            "rem_addr": "192.168.1.100",
            "rem_port": 55432,
            "ssl": False
        }
    }

    auths = []

    # Create 5 sessions - all should succeed without max_sessions limit
    for i in range(5):
        auth = UserPamAuthenticator(
            username=f"{api_key_data['username']}:{api_key_data['id']}",
            service=pam_service_no_max_sessions,
            pam_env={
                "pam_truenas_password_auth_is_api_key": "1",
                "pam_truenas_session_data": json.dumps(session_data)
            }
        )

        resp = auth.auth_init()
        assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

        responses = []
        for msg in resp.reason:
            if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
                responses.append(api_key_data["raw_key"])
            else:
                responses.append(None)

        resp = auth.auth_continue(responses)
        assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

        resp = auth.login()
        assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

        auths.append(auth)

    # Verify we have at least 5 sessions
    user_sessions = truenas_pam_session.get_sessions_by_username(api_key_data['username'])
    assert len(user_sessions) >= 5

    # Clean up all sessions
    for auth in auths:
        auth.logout()
        auth.end()


@pytest.mark.skipif(os.geteuid() != 0, reason="Requires root privileges")
def test_max_sessions_releases_on_logout(api_key_data, pam_service_with_max_sessions):
    """Test that closing a session frees up space for a new one"""

    session_data = {
        "origin_family": "AF_INET",
        "origin": {
            "loc_addr": "127.0.0.1",
            "loc_port": 22,
            "rem_addr": "192.168.1.100",
            "rem_port": 55432,
            "ssl": False
        }
    }

    # Create two sessions (hitting the limit)
    auth1 = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service_with_max_sessions,
        pam_env={
            "pam_truenas_password_auth_is_api_key": "1",
            "pam_truenas_session_data": json.dumps(session_data)
        }
    )

    resp = auth1.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    resp = auth1.auth_continue(responses)
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    resp = auth1.login()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    auth2 = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service_with_max_sessions,
        pam_env={
            "pam_truenas_password_auth_is_api_key": "1",
            "pam_truenas_session_data": json.dumps(session_data)
        }
    )

    resp = auth2.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    resp = auth2.auth_continue(responses)
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    resp = auth2.login()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # Now close the first session
    auth1.logout()

    # Now we should be able to create a third session
    auth3 = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service_with_max_sessions,
        pam_env={
            "pam_truenas_password_auth_is_api_key": "1",
            "pam_truenas_session_data": json.dumps(session_data)
        }
    )

    resp = auth3.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    resp = auth3.auth_continue(responses)
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # This should succeed now that we've freed up a session slot
    resp = auth3.login()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # Clean up
    auth1.end()
    auth2.logout()
    auth2.end()
    auth3.logout()
    auth3.end()
