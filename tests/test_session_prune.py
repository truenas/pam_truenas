"""Tests for truenas_pam_session.prune_sessions()

pam_truenas prunes sessions of exited processes only while counting a user's
sessions for max_sessions. middlewared calls prune_sessions() for the rest.
"""

import os

import pytest
import truenas_keyring
import truenas_pam_session
from truenas_pam_session import PAM_KEYRING_NAME
from raw_pam import PAM_SUCCESS, other_smbd, pam_service, smb_claim_session, smb_close_session


def sessions(username, pid):
    return [s for s in truenas_pam_session.get_sessions_by_username(username) if s.pid == pid]


@pytest.fixture
def service():
    yield from pam_service()


def test_prune_sessions_of_exited_process(api_key_data, service):
    """Only sessions whose process has exited are removed"""
    user = api_key_data["username"]

    assert smb_claim_session(service, user, "smb/1") == PAM_SUCCESS
    with other_smbd(service, user, "smb/2") as (exited_pid, rc):
        assert rc == PAM_SUCCESS

    with other_smbd(service, user, "smb/3") as (live_pid, rc):
        assert rc == PAM_SUCCESS

        assert truenas_pam_session.prune_sessions() >= 1
        assert sessions(user, exited_pid) == []
        assert len(sessions(user, live_pid)) == 1
        assert len(sessions(user, os.getpid())) == 1

    assert smb_close_session(service, user, "smb/1") == PAM_SUCCESS


def test_prune_sessions_skips_user_without_sessions(api_key_data, service):
    """A user keyring without SESSIONS, as one holding only API keys can be,
    is skipped"""
    user = api_key_data["username"]

    with other_smbd(service, user, "smb/1") as (exited_pid, rc):
        assert rc == PAM_SUCCESS

    pam_keyring = truenas_keyring.get_persistent_keyring().search(
        key_type=truenas_keyring.KeyType.KEYRING, description=PAM_KEYRING_NAME
    )
    no_sessions = truenas_keyring.add_keyring(
        description="test_prune_no_sessions", target_keyring=pam_keyring.key.serial
    )
    try:
        assert truenas_pam_session.prune_sessions() >= 1
        assert sessions(user, exited_pid) == []
    finally:
        pam_keyring.unlink_key(no_sessions.key.serial)
