#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later

"""
TrueNAS PAM Session Iterator

This module provides functionality to read and iterate over PAM sessions
stored in the kernel keyring by the pam_truenas module.
"""

import struct
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Optional
import socket
import ipaddress
import json
import truenas_keyring

# Constants matching the C definitions
PAM_KEYRING_NAME = "PAM_TRUENAS"
PAM_SESSION_NAME = "SESSIONS"
LOGIN_NAME_MAX = 256
NAME_MAX = 255
SECURITY_LABEL_MAX = 256

# Address family constants
AF_UNIX = socket.AF_UNIX
AF_INET = socket.AF_INET
AF_INET6 = socket.AF_INET6

# Struct format for unpacking the 4096-byte mdb_sess_t
# Based on the C struct layout with proper alignment
MDB_SESS_STRUCT = (
    "16s"    # struct timespec (8 + 8 bytes)
    "16s"    # uuid_t session_id
    "i"      # pid_t pid
    "i"      # pid_t sid
    "I"      # uint32_t flags
    "i"      # int origin_family
    # mdb_cred_t (264 bytes)
    "256s"   # char name[LOGIN_NAME_MAX]
    "I"      # uid_t uid
    "I"      # gid_t gid
    # mdb_origin_t union (272 bytes)
    "272s"   # Union data
    # mdb_pam_item_t (1020 bytes)
    "255s"   # char service[NAME_MAX]
    "255s"   # char ruser[NAME_MAX]
    "255s"   # char rhost[NAME_MAX]
    "255s"   # char tty[NAME_MAX]
    # json_data (2492 bytes)
    "2492s"  # char json_data[2492]
)

# Offsets into unpacked MDB_SESS_STRUCT tuple
OFFSET_TIMESPEC = 0
OFFSET_SESSION_ID = 1
OFFSET_PID = 2
OFFSET_SID = 3
OFFSET_FLAGS = 4
OFFSET_ORIGIN_FAMILY = 5
OFFSET_CRED_NAME = 6
OFFSET_CRED_UID = 7
OFFSET_CRED_GID = 8
OFFSET_ORIGIN_DATA = 9
OFFSET_PAM_SERVICE = 10
OFFSET_PAM_RUSER = 11
OFFSET_PAM_RHOST = 12
OFFSET_PAM_TTY = 13
OFFSET_JSON_DATA = 14

# Struct format for Unix origin
UNIX_ORIGIN_STRUCT = (
    "i"      # pid_t pid
    "I"      # uid_t uid
    "I"      # gid_t gid
    "I"      # uid_t loginuid
    "256s"   # char sec[SECURITY_LABEL_MAX]
)

# Offsets into unpacked UNIX_ORIGIN_STRUCT tuple
UNIX_OFFSET_PID = 0
UNIX_OFFSET_UID = 1
UNIX_OFFSET_GID = 2
UNIX_OFFSET_LOGINUID = 3
UNIX_OFFSET_SEC_LABEL = 4

# Struct format for TCP origin (reordered to avoid padding)
TCP_ORIGIN_STRUCT = (
    "16s"    # struct in6_addr loc_addr (offset 0)
    "16s"    # struct in6_addr rem_addr (offset 16)
    "H"      # uint16_t loc_port (offset 32)
    "H"      # uint16_t rem_port (offset 34)
    "?"      # bool ssl (offset 36)
    "3x"     # 3 bytes padding to reach 40 bytes
)

# Offsets into unpacked TCP_ORIGIN_STRUCT tuple
TCP_OFFSET_LOC_ADDR = 0
TCP_OFFSET_REM_ADDR = 1
TCP_OFFSET_LOC_PORT = 2
TCP_OFFSET_REM_PORT = 3
TCP_OFFSET_SSL = 4

# Type alias for IP addresses
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

@dataclass
class PamUnixOrigin:
    pid: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    loginuid: Optional[int] = None
    security_label: Optional[str] = None


@dataclass
class PamTcpOrigin:
    local_addr: Optional[IPAddress] = None
    local_port: Optional[int] = None
    remote_addr: Optional[IPAddress] = None
    remote_port: Optional[int] = None
    ssl: Optional[bool] = None


@dataclass
class PamSession:
    """PAM session information stored in kernel keyring"""
    # Session metadata
    session_id: uuid.UUID
    creation: datetime
    pid: int
    sid: int
    flags: int

    # User credentials
    username: str
    uid: int
    gid: int

    # PAM items
    service: str
    ruser: str
    rhost: str
    tty: str

    # Origin information
    origin_family: str  # "AF_UNIX", "AF_INET", "AF_INET6", or "Unknown"
    origin: PamUnixOrigin | PamTcpOrigin | None = None

    # Extra JSON data
    extra_data: Optional[dict] = None  # Parsed JSON data, None if empty or invalid


class SessionIterator:
    """Iterator for PAM sessions stored in kernel keyring"""

    def __init__(self):
        """
        Initialize session iterator
        """
        self.pam_keyring = None
        # Get the persistent keyring
        persistent = truenas_keyring.get_persistent_keyring()

        # Use search() method to find the PAM_TRUENAS keyring within persistent keyring
        self.pam_keyring = persistent.search(
            key_type=truenas_keyring.KeyType.KEYRING,
            description=PAM_KEYRING_NAME
        )

    def _decode_session(self, key_desc: str, value: bytes) -> PamSession:
        """Decode a session from keyring data"""
        # Unpack the entire struct
        unpacked = struct.unpack(MDB_SESS_STRUCT, value)

        # Parse timespec
        timespec_bytes = unpacked[OFFSET_TIMESPEC]
        tv_sec, tv_nsec = struct.unpack("qq", timespec_bytes)
        creation = datetime.fromtimestamp(tv_sec + tv_nsec / 1_000_000_000)

        # Parse UUID
        session_id = uuid.UUID(bytes=unpacked[OFFSET_SESSION_ID])

        # Basic fields
        pid = unpacked[OFFSET_PID]
        sid = unpacked[OFFSET_SID]
        flags = unpacked[OFFSET_FLAGS]
        origin_family_int = unpacked[OFFSET_ORIGIN_FAMILY]

        # Parse credentials
        username = unpacked[OFFSET_CRED_NAME].rstrip(b'\x00').decode('utf-8')
        uid = unpacked[OFFSET_CRED_UID]
        gid = unpacked[OFFSET_CRED_GID]

        # Determine origin family name
        if origin_family_int == AF_UNIX:
            origin_family = "AF_UNIX"
        elif origin_family_int == AF_INET:
            origin_family = "AF_INET"
        elif origin_family_int == AF_INET6:
            origin_family = "AF_INET6"
        else:
            origin_family = f"Unknown({origin_family_int})"

        # Initialize session with required fields
        session = PamSession(
            session_id=session_id,
            creation=creation,
            pid=pid,
            sid=sid,
            flags=flags,
            username=username,
            uid=uid,
            gid=gid,
            service=unpacked[OFFSET_PAM_SERVICE].rstrip(b'\x00').decode('utf-8'),
            ruser=unpacked[OFFSET_PAM_RUSER].rstrip(b'\x00').decode('utf-8'),
            rhost=unpacked[OFFSET_PAM_RHOST].rstrip(b'\x00').decode('utf-8'),
            tty=unpacked[OFFSET_PAM_TTY].rstrip(b'\x00').decode('utf-8'),
            origin_family=origin_family
        )

        # Parse origin union based on family
        origin_data = unpacked[OFFSET_ORIGIN_DATA]
        if origin_family_int == AF_UNIX:
            # Unpack Unix origin
            unix_unpacked = struct.unpack(UNIX_ORIGIN_STRUCT, origin_data[:272])
            session.origin = PamUnixOrigin(
                pid=unix_unpacked[UNIX_OFFSET_PID],
                uid=unix_unpacked[UNIX_OFFSET_UID],
                gid=unix_unpacked[UNIX_OFFSET_GID],
                loginuid=unix_unpacked[UNIX_OFFSET_LOGINUID],
                security_label=unix_unpacked[UNIX_OFFSET_SEC_LABEL].rstrip(b'\x00').decode('utf-8')
            )

        elif origin_family_int in (AF_INET, AF_INET6):
            # Unpack TCP origin
            tcp_unpacked = struct.unpack(TCP_ORIGIN_STRUCT, origin_data[:40])

            # Convert addresses based on family
            if origin_family_int == AF_INET:
                # IPv4 addresses are stored in first 4 bytes of the 16-byte field
                # inet_pton stores them in network byte order which IPv4Address expects
                local_addr = ipaddress.IPv4Address(tcp_unpacked[TCP_OFFSET_LOC_ADDR][:4])
                remote_addr = ipaddress.IPv4Address(tcp_unpacked[TCP_OFFSET_REM_ADDR][:4])
            else:
                # IPv6 addresses use all 16 bytes
                local_addr = ipaddress.IPv6Address(tcp_unpacked[TCP_OFFSET_LOC_ADDR])
                remote_addr = ipaddress.IPv6Address(tcp_unpacked[TCP_OFFSET_REM_ADDR])

            session.origin = PamTcpOrigin(
                local_addr=local_addr,
                local_port=tcp_unpacked[TCP_OFFSET_LOC_PORT],
                remote_addr=remote_addr,
                remote_port=tcp_unpacked[TCP_OFFSET_REM_PORT],
                ssl=tcp_unpacked[TCP_OFFSET_SSL]
            )

        # Parse JSON data
        json_str = unpacked[OFFSET_JSON_DATA].rstrip(b'\x00').decode('utf-8')
        if json_str:
            try:
                session.extra_data = json.loads(json_str)
            except json.JSONDecodeError:
                # Store raw string if JSON parsing fails
                session.extra_data = {"_raw": json_str}

        return session

    def iterate(self) -> Iterator[PamSession]:
        """
        Iterate over all sessions in the kernel keyring

        Yields:
            PamSession objects for each session in the keyring
        """
        # The PAM_TRUENAS keyring contains username-based sub-keyrings
        # Structure: PAM_TRUENAS -> username -> SESSIONS -> session_keys

        # Iterate through all username keyrings under PAM_TRUENAS
        for user_keyring in self.pam_keyring.iter_keyring_contents(unlink_revoked=True, unlink_expired=True):
            # This is a username keyring, now find the SESSIONS keyring under it
            sessions_keyring = user_keyring.search(
                key_type=truenas_keyring.KeyType.KEYRING,
                description=PAM_SESSION_NAME
            )

            # Iterate through the sessions in the SESSIONS keyring
            for session_key in sessions_keyring.iter_keyring_contents(unlink_revoked=True, unlink_expired=True):
                try:
                    # Read the session data from the key
                    data = session_key.read_data()
                    session = self._decode_session(session_key.description, data)
                    yield session
                except Exception:
                    # We can in theory have TOCTOU on key
                    pass

    def get_sessions(self) -> list[PamSession]:
        """
        Get a list of all sessions in the keyring

        Returns:
            List of PamSession objects
        """
        return list(self.iterate())

    def get_session_by_id(self, session_id: str | uuid.UUID) -> Optional[PamSession]:
        """
        Get a specific session by UUID

        Args:
            session_id: UUID as string or UUID object

        Returns:
            PamSession if found, None otherwise
        """
        if isinstance(session_id, str):
            session_id = uuid.UUID(session_id)

        for session in self.iterate():
            if session.session_id == session_id:
                return session

        return None

    def get_sessions_by_username(self, username: str) -> list[PamSession]:
        """
        Get all sessions for a specific username

        Args:
            username: Username to search for

        Returns:
            List of PamSession objects for the user
        """
        sessions = []

        # Try to directly access the username-specific keyring within PAM_TRUENAS
        user_keyring = self.pam_keyring.search(
            key_type=truenas_keyring.KeyType.KEYRING,
            description=username
        )

        # Now find the SESSIONS keyring under this user
        sessions_keyring = user_keyring.search(
            key_type=truenas_keyring.KeyType.KEYRING,
            description=PAM_SESSION_NAME
        )

        # Iterate through the sessions for this specific user
        for session_key in sessions_keyring.iter_keyring_contents(unlink_revoked=True, unlink_expired=True):
            try:
                # Read the session data from the key
                data = session_key.read_data()
                session = self._decode_session(session_key.description, data)
            except Exception:
                # Skip malformed entries or inaccessible keys
                continue
            else:
                sessions.append(session)

        return sessions


# Convenience functions
def get_sessions() -> list[PamSession]:
    """
    Get all sessions from the kernel keyring

    Returns:
        List of PamSession objects
    """
    iterator = SessionIterator()
    return iterator.get_sessions()


def iterate_sessions() -> Iterator[PamSession]:
    """
    Iterate over sessions in the kernel keyring

    Yields:
        PamSession objects
    """
    iterator = SessionIterator()
    return iterator.iterate()


def get_session_by_id(session_id: str | uuid.UUID) -> Optional[PamSession]:
    """
    Get a specific session by UUID

    Args:
        session_id: UUID as string or UUID object

    Returns:
        PamSession if found, None otherwise
    """
    iterator = SessionIterator()
    return iterator.get_session_by_id(session_id)


def get_sessions_by_username(username: str) -> list[PamSession]:
    """
    Get all sessions for a specific username

    Args:
        username: Username to search for

    Returns:
        List of PamSession objects for the user
    """
    iterator = SessionIterator()
    return iterator.get_sessions_by_username(username)
