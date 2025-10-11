"""Tests for PAM session management with kernel keyrings"""

import json
import os
import pwd
import uuid
from pathlib import Path
import pytest
import truenas_pypam
from truenas_authenticator import UserPamAuthenticator, AuthenticatorStage
import truenas_pam_session


@pytest.mark.parametrize("origin_family,origin_data", [
    ("AF_INET", {
        "loc_addr": "127.0.0.1",
        "loc_port": 22,
        "rem_addr": "192.168.1.100",
        "rem_port": 55432,
        "ssl": False
    }),
    ("AF_UNIX", {
        "pid": 12345,
        "uid": 1000,
        "gid": 1000,
        "loginuid": 1000,
        "sec": "unconfined"
    })
])
def test_session_created_on_login(api_key_data, pam_service, tmp_path, origin_family, origin_data):
    """Test that a session is created in the kernel keyring when a user logs in"""

    # Set session data in PAM environment
    session_data = {
        "origin_family": origin_family,
        "origin": origin_data,
        "extra": {
            "client": "test_client",
            "version": "1.0.0"
        }
    }

    # Create authenticator with session data in PAM environment
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={
            "pam_truenas_password_auth_is_api_key": "1",
            "pam_truenas_session_data": json.dumps(session_data)
        }
    )

    # Initialize authentication
    resp = auth.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    assert resp.stage == AuthenticatorStage.AUTH

    # Provide API key as password response
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(api_key_data["raw_key"])
        else:
            responses.append(None)

    # Continue authentication with API key
    resp = auth.auth_continue(responses)
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    assert auth.state.stage == AuthenticatorStage.LOGIN

    # Login (this will open session and create keyring entry)
    resp = auth.login()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # Get session UUID from PAM environment using ctx
    pam_env = auth.ctx.env_dict()
    session_uuid = pam_env.get("pam_truenas_session_uuid")
    assert session_uuid is not None

    # Read session from keyring using Python module
    sessions = truenas_pam_session.get_sessions()
    assert len(sessions) > 0

    # Find our session by UUID
    session = truenas_pam_session.get_session_by_id(session_uuid)
    assert session is not None

    # Verify session data
    assert session.username == api_key_data['username']
    assert session.service == pam_service

    # Verify origin family
    assert session.origin_family == origin_family

    # Verify origin-specific data
    if origin_family == "AF_INET":
        assert session.origin is not None
        assert str(session.origin.remote_addr) == "192.168.1.100"
        assert session.origin.remote_port == 55432
        assert session.origin.local_port == 22
        assert session.origin.ssl is False
    elif origin_family == "AF_UNIX":
        assert session.origin is not None
        assert session.origin.pid == 12345
        assert session.origin.uid == 1000
        assert session.origin.gid == 1000

    # Verify extra data
    assert session.extra_data is not None
    assert "extra" in session.extra_data
    assert session.extra_data["extra"].get("client") == "test_client"
    assert session.extra_data["extra"].get("version") == "1.0.0"

    # Logout (closes session and removes from keyring)
    resp = auth.logout()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # Verify session is removed
    session = truenas_pam_session.get_session_by_id(session_uuid)
    assert session is None

    # Clean up
    auth.end()


def test_multiple_user_sessions(api_key_data, pam_service):
    """Test that multiple sessions can exist for the same user"""

    # Create multiple authenticators for the same user
    auths = []
    session_uuids = []

    for i in range(3):
        session_data = {
            "origin_family": "AF_INET",
            "origin": {
                "loc_addr": "127.0.0.1",
                "loc_port": 22,
                "rem_addr": f"192.168.1.{100 + i}",
                "rem_port": 55432 + i,
                "ssl": False
            },
            "extra": {"session_num": i}
        }

        auth = UserPamAuthenticator(
            username=f"{api_key_data['username']}:{api_key_data['id']}",
            service=pam_service,
            pam_env={
                "pam_truenas_password_auth_is_api_key": "1",
                "pam_truenas_session_data": json.dumps(session_data)
            }
        )

        # Authenticate
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

        # Login (opens session)
        resp = auth.login()
        assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

        # Get session UUID from PAM environment
        pam_env = auth.ctx.env_dict()
        session_uuid = pam_env.get("pam_truenas_session_uuid")
        assert session_uuid is not None
        session_uuids.append(session_uuid)
        auths.append(auth)

    # Verify all sessions exist
    assert len(session_uuids) == 3

    # Get all sessions for the user
    user_sessions = truenas_pam_session.get_sessions_by_username(api_key_data['username'])
    assert len(user_sessions) >= 3  # May have other sessions from other tests

    # Verify our sessions are present
    our_session_ids = set(session_uuids)
    found_session_ids = {str(s.session_id) for s in user_sessions}
    assert our_session_ids.issubset(found_session_ids)

    # Logout all sessions
    for auth in auths:
        resp = auth.logout()
        assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
        auth.end()

    # Verify sessions are removed
    for session_uuid in session_uuids:
        session = truenas_pam_session.get_session_by_id(session_uuid)
        assert session is None


def test_session_data_persistence(api_key_data, pam_service):
    """Test that session data persists correctly in the kernel keyring"""

    # Complex session data with all fields
    session_data = {
        "origin_family": "AF_INET",
        "origin": {
            "loc_addr": "10.0.0.1",
            "loc_port": 443,
            "rem_addr": "203.0.113.5",
            "rem_port": 62345,
            "ssl": True
        },
        "extra": {
            "protocol": "https",
            "user_agent": "Mozilla/5.0",
            "session_type": "web",
            "metadata": {
                "nested": "data",
                "array": [1, 2, 3]
            }
        }
    }

    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={
            "pam_truenas_password_auth_is_api_key": "1",
            "pam_truenas_session_data": json.dumps(session_data)
        }
    )

    # Authenticate
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

    # Login (opens session)
    resp = auth.login()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # Get session UUID from PAM environment
    pam_env = auth.ctx.env_dict()
    session_uuid = pam_env.get("pam_truenas_session_uuid")
    assert session_uuid is not None

    # Read back and verify all data
    session = truenas_pam_session.get_session_by_id(session_uuid)
    assert session is not None

    # Verify TCP origin data
    assert session.origin_family == "AF_INET"
    assert session.origin is not None
    assert str(session.origin.local_addr) == "10.0.0.1"
    assert session.origin.local_port == 443
    assert str(session.origin.remote_addr) == "203.0.113.5"
    assert session.origin.remote_port == 62345
    assert session.origin.ssl is True

    # Verify extra JSON data (nested under 'extra' key)
    assert session.extra_data is not None
    assert "extra" in session.extra_data
    assert session.extra_data["extra"]["protocol"] == "https"
    assert session.extra_data["extra"]["user_agent"] == "Mozilla/5.0"
    assert session.extra_data["extra"]["session_type"] == "web"
    assert "metadata" in session.extra_data["extra"]
    assert session.extra_data["extra"]["metadata"]["nested"] == "data"
    assert session.extra_data["extra"]["metadata"]["array"] == [1, 2, 3]

    # Clean up
    resp = auth.logout()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS
    auth.end()


@pytest.mark.skipif(os.geteuid() != 0, reason="Requires root privileges")
def test_session_survives_privilege_drop(api_key_data, pam_service):
    """Test that session can be closed after privilege drop."""
    # Get the test user's info
    test_user = pwd.getpwnam(api_key_data['username'])

    # Create session data
    session_data = {
        "origin_family": "AF_INET",
        "origin": {
            "loc_addr": "127.0.0.1",
            "loc_port": 22,
            "rem_addr": "192.168.1.100",
            "rem_port": 55432,
            "ssl": False
        },
        "extra": {
            "test": "privilege_drop"
        }
    }

    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service,
        pam_env={
            "pam_truenas_password_auth_is_api_key": "1",
            "pam_truenas_session_data": json.dumps(session_data)
        }
    )

    # Authenticate as root
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

    # Open session as root
    resp = auth.login()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # Get session UUID
    pam_env = auth.ctx.env_dict()
    session_uuid = pam_env.get("pam_truenas_session_uuid")
    assert session_uuid is not None

    # Verify session exists
    session = truenas_pam_session.get_session_by_id(session_uuid)
    assert session is not None

    # Drop privileges to the test user (using seteuid/setegid to allow switching back)
    os.setegid(test_user.pw_gid)
    os.seteuid(test_user.pw_uid)

    # Close session as the test user - should work because keyring is accessible
    resp = auth.logout()
    assert resp.code == truenas_pypam.PAMCode.PAM_SUCCESS

    # Reset privileges to root to verify session was removed
    os.seteuid(0)
    os.setegid(0)

    # Verify session is removed
    session = truenas_pam_session.get_session_by_id(session_uuid)
    assert session is None

    auth.end()