"""Tests for sessions closed on a different PAM handle than they were opened on

Samba opens and closes each SMB session with its own PAM handle
(smb_pam_claim_session() / smb_pam_close_session()), while middlewared keeps
many handles open in one process.
"""

import os

import pytest
import truenas_pam_session
from raw_pam import (
    PAM_PERM_DENIED, PAM_SUCCESS, PamHandle, other_smbd, pam_service,
    smb_claim_session, smb_close_session, tcp_session_data,
)


def sessions(username, pid=None):
    return [s for s in truenas_pam_session.get_sessions_by_username(username)
            if pid is None or s.pid == pid]


@pytest.fixture
def smb_service():
    yield from pam_service()


@pytest.fixture
def smb_service_max_sessions():
    yield from pam_service("max_sessions=2")


def test_close_on_other_handle(api_key_data, smb_service):
    """A session opened on one handle is closed from another"""
    user = api_key_data["username"]

    assert smb_claim_session(smb_service, user, "smb/1") == PAM_SUCCESS
    assert [s.tty for s in sessions(user, os.getpid())] == ["smb/1"]

    assert smb_close_session(smb_service, user, "smb/1") == PAM_SUCCESS
    assert sessions(user, os.getpid()) == []


def test_close_on_other_handle_matches_tty(api_key_data, smb_service):
    """Only the session with the closing handle's tty is closed"""
    user = api_key_data["username"]

    for tty in ("smb/1", "smb/2"):
        assert smb_claim_session(smb_service, user, tty) == PAM_SUCCESS

    assert smb_close_session(smb_service, user, "smb/2") == PAM_SUCCESS
    assert [s.tty for s in sessions(user, os.getpid())] == ["smb/1"]

    assert smb_close_session(smb_service, user, "smb/1") == PAM_SUCCESS
    assert sessions(user, os.getpid()) == []


def test_close_on_other_handle_spares_sessions_without_tty(api_key_data, smb_service):
    """Sessions held on many handles in one process, as middlewared holds them,
    are only closed on their own handle"""
    user = api_key_data["username"]

    handles = []
    for port in range(55000, 55003):
        handle = PamHandle(smb_service, user, session_data=tcp_session_data(port))
        assert handle.open_session() == PAM_SUCCESS
        handles.append(handle)

    assert smb_close_session(smb_service, user, None) == PAM_SUCCESS
    assert smb_close_session(smb_service, user, "smb/1") == PAM_SUCCESS
    assert len(sessions(user, os.getpid())) == 3

    for handle in handles:
        assert handle.close_session() == PAM_SUCCESS
        handle.end()

    assert sessions(user, os.getpid()) == []


def test_handle_closes_only_its_own_session(api_key_data, smb_service):
    """A handle that opened a session never closes another, even one with the
    same tty"""
    user = api_key_data["username"]

    first = PamHandle(smb_service, user, tty="pts/0")
    second = PamHandle(smb_service, user, tty="pts/0")
    assert first.open_session() == PAM_SUCCESS
    assert second.open_session() == PAM_SUCCESS

    assert first.close_session() == PAM_SUCCESS
    assert first.close_session() == PAM_SUCCESS
    assert len(sessions(user, os.getpid())) == 1

    assert second.close_session() == PAM_SUCCESS
    first.end()
    second.end()
    assert sessions(user, os.getpid()) == []


def test_max_sessions_counts_each_session(api_key_data, smb_service_max_sessions):
    """Every open session counts toward max_sessions=2, including several opened
    by one process. Closed sessions and those of exited processes do not."""
    user = api_key_data["username"]
    service = smb_service_max_sessions

    assert smb_claim_session(service, user, "smb/1") == PAM_SUCCESS
    assert smb_claim_session(service, user, "smb/2") == PAM_SUCCESS
    assert smb_claim_session(service, user, "smb/3") == PAM_PERM_DENIED

    assert smb_close_session(service, user, "smb/2") == PAM_SUCCESS
    with other_smbd(service, user, "smb/11") as (_, rc):
        assert rc == PAM_SUCCESS
        assert smb_claim_session(service, user, "smb/3") == PAM_PERM_DENIED

    # The other process exited without closing its session, which no longer counts
    assert smb_claim_session(service, user, "smb/3") == PAM_SUCCESS

    for tty in ("smb/1", "smb/3"):
        assert smb_close_session(service, user, tty) == PAM_SUCCESS
