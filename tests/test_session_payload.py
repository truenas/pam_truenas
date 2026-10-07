"""Tests for the session key payload

A session is stored as kr_sess_hdr_t followed by its strings
(src/kr_session.h), so each session costs uid 0's key quota what it uses
rather than the 4 KiB of kr_sess_t.
"""

import ipaddress
import os
import pwd

import pytest
import truenas_keyring
import truenas_pam_session
from truenas_pam_session import PAM_KEYRING_NAME, PAM_SESSION_NAME
from raw_pam import PAM_SUCCESS, PamHandle, pam_service, tcp_session_data

EXTRA = {"extra": {"secure_transport": True}}

UNIX_SESSION_DATA = {
    "origin_family": "AF_UNIX",
    "origin": {
        "pid": 12345,
        "uid": 1000,
        "gid": 1001,
        "loginuid": 1000,
        "sec": "unconfined"
    },
} | EXTRA


@pytest.fixture
def service():
    yield from pam_service()


def open_session(service, user, **kwargs):
    handle = PamHandle(service, user, **kwargs)
    assert handle.open_session() == PAM_SUCCESS
    return handle, handle.getenv("pam_truenas_session_uuid")


def close_session(handle):
    assert handle.close_session() == PAM_SUCCESS
    handle.end()


def session_payload(username, session_uuid):
    persistent = truenas_keyring.get_persistent_keyring()
    pam_keyring = persistent.search(key_type="keyring", description=PAM_KEYRING_NAME)
    user_keyring = pam_keyring.search(key_type="keyring", description=username)
    sessions = user_keyring.search(key_type="keyring", description=PAM_SESSION_NAME)
    key = sessions.search(key_type="user", description=f"{session_uuid}:{os.getpid()}")
    return key.read_data()


@pytest.mark.parametrize("session_data", [
    None,
    tcp_session_data(55432) | EXTRA,
    tcp_session_data(55433, "AF_INET6"),
    UNIX_SESSION_DATA,
], ids=["no_origin", "AF_INET", "AF_INET6", "AF_UNIX"])
def test_session_round_trip(api_key_data, service, session_data):
    """Every field of a session reads back as it was stored"""
    user = api_key_data["username"]
    handle, session_uuid = open_session(service, user, tty="smb/7",
                                        rhost="client.example",
                                        session_data=session_data)

    session = truenas_pam_session.get_session_by_id(session_uuid)
    assert session is not None

    passwd = pwd.getpwnam(user)
    assert (session.username, session.uid, session.gid) == (user, passwd.pw_uid, passwd.pw_gid)
    assert session.pid == os.getpid()
    assert session.sid == os.getsid(0)
    assert (session.service, session.ruser, session.rhost, session.tty) == \
        (service, "", "client.example", "smb/7")

    if session_data is None:
        assert session.origin_family == "Unknown(0)"
        assert session.origin is None
        assert session.extra_data is None
    elif session_data["origin_family"] == "AF_UNIX":
        assert session.origin_family == "AF_UNIX"
        assert session.origin == truenas_pam_session.PamUnixOrigin(
            pid=12345, uid=1000, gid=1001, loginuid=1000, security_label="unconfined"
        )
        assert session.extra_data == EXTRA
    else:
        origin = session_data["origin"]
        assert session.origin_family == session_data["origin_family"]
        assert session.origin == truenas_pam_session.PamTcpOrigin(
            local_addr=ipaddress.ip_address(origin["loc_addr"]),
            local_port=origin["loc_port"],
            remote_addr=ipaddress.ip_address(origin["rem_addr"]),
            remote_port=origin["rem_port"],
            ssl=origin["ssl"]
        )
        assert session.extra_data == ({"extra": session_data["extra"]}
                                      if "extra" in session_data else None)

    close_session(handle)


def test_session_payload_size(api_key_data, service):
    """A middlewared-style session takes a few hundred bytes, not 4 KiB"""
    user = api_key_data["username"]
    handle, session_uuid = open_session(service, user,
                                        session_data=tcp_session_data(55432) | EXTRA)

    assert len(session_payload(user, session_uuid)) < 512

    close_session(handle)


def test_session_long_strings(api_key_data, service):
    """Strings longer than a session holds are stored truncated"""
    user = api_key_data["username"]
    handle, session_uuid = open_session(service, user, tty="t" * 300, rhost="r" * 300,
                                        session_data={"extra": {"blob": "b" * 3000}})

    session = truenas_pam_session.get_session_by_id(session_uuid)
    assert session.tty == "t" * 254
    assert session.rhost == "r" * 254
    # JSON cut short no longer parses and is returned raw
    assert len(session.extra_data["_raw"]) == 2491

    close_session(handle)
