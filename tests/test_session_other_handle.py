"""Tests for a session opened on one PAM context and closed on another in the
same process
"""

import os

import pytest
import truenas_pam_session
from raw_pam import (
    PAM_PERM_DENIED, PAM_SUCCESS, PamHandle, close_in_new_context, open_in_new_context,
    other_process, pam_service, tcp_session_data,
)


def sessions(username, pid=None):
    return [s for s in truenas_pam_session.get_sessions_by_username(username)
            if pid is None or s.pid == pid]


@pytest.fixture
def service():
    yield from pam_service()


@pytest.fixture
def service_max_sessions():
    yield from pam_service("max_sessions=2")


def test_close_on_other_handle(api_key_data, service):
    """A session opened on one PAM context is closed on another in the same
    process"""
    user = api_key_data["username"]

    assert open_in_new_context(service, user, "tty1") == PAM_SUCCESS
    assert [s.tty for s in sessions(user, os.getpid())] == ["tty1"]

    assert close_in_new_context(service, user, "tty1") == PAM_SUCCESS
    assert sessions(user, os.getpid()) == []


def test_close_on_other_handle_matches_tty(api_key_data, service):
    """Only the session with the closing context's tty is closed"""
    user = api_key_data["username"]

    for tty in ("tty1", "tty2"):
        assert open_in_new_context(service, user, tty) == PAM_SUCCESS

    assert close_in_new_context(service, user, "tty2") == PAM_SUCCESS
    assert [s.tty for s in sessions(user, os.getpid())] == ["tty1"]

    assert close_in_new_context(service, user, "tty1") == PAM_SUCCESS
    assert sessions(user, os.getpid()) == []


def test_close_on_other_handle_spares_sessions_without_tty(api_key_data, service):
    """Sessions held on many contexts in one process, as middlewared holds them,
    are only closed on their own context"""
    user = api_key_data["username"]

    handles = []
    for port in range(55000, 55003):
        handle = PamHandle(service, user, session_data=tcp_session_data(port))
        assert handle.open_session() == PAM_SUCCESS
        handles.append(handle)

    assert close_in_new_context(service, user, None) == PAM_SUCCESS
    assert close_in_new_context(service, user, "tty1") == PAM_SUCCESS
    assert len(sessions(user, os.getpid())) == 3

    for handle in handles:
        assert handle.close_session() == PAM_SUCCESS
        handle.end()

    assert sessions(user, os.getpid()) == []


def test_handle_closes_only_its_own_session(api_key_data, service):
    """A context that opened a session never closes another, even one with the
    same tty"""
    user = api_key_data["username"]

    first = PamHandle(service, user, tty="pts/0")
    second = PamHandle(service, user, tty="pts/0")
    assert first.open_session() == PAM_SUCCESS
    assert second.open_session() == PAM_SUCCESS

    assert first.close_session() == PAM_SUCCESS
    assert first.close_session() == PAM_SUCCESS
    assert len(sessions(user, os.getpid())) == 1

    assert second.close_session() == PAM_SUCCESS
    first.end()
    second.end()
    assert sessions(user, os.getpid()) == []


def test_max_sessions_counts_each_session(api_key_data, service_max_sessions):
    """Every open session counts toward max_sessions=2, including several opened
    by one process. Closed sessions and those of exited processes do not."""
    user = api_key_data["username"]
    service = service_max_sessions

    assert open_in_new_context(service, user, "tty1") == PAM_SUCCESS
    assert open_in_new_context(service, user, "tty2") == PAM_SUCCESS
    assert open_in_new_context(service, user, "tty3") == PAM_PERM_DENIED

    assert close_in_new_context(service, user, "tty2") == PAM_SUCCESS
    with other_process(service, user, "tty11") as (_, rc):
        assert rc == PAM_SUCCESS
        assert open_in_new_context(service, user, "tty3") == PAM_PERM_DENIED

    # The other process exited without closing its session, which no longer counts
    assert open_in_new_context(service, user, "tty3") == PAM_SUCCESS

    for tty in ("tty1", "tty3"):
        assert close_in_new_context(service, user, tty) == PAM_SUCCESS
