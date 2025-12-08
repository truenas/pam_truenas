#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-or-later

"""
TrueNAS PAM Faillog Iterator

This module provides functionality to read and iterate over PAM failure log
entries stored in the kernel keyring by the pam_truenas module.
"""

import errno
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Iterator, Dict, Any
import truenas_keyring

# Constants matching the C definitions
PAM_KEYRING_NAME = "PAM_TRUENAS"
PAM_FAILLOG_NAME = "FAILLOG"
PAM_TALLY_LOCK_NAME = 'tally_lock'
NAME_MAX = 255

# Tally flags from tally.h
TALLY_FLAG_RHOST = 0x00000001
TALLY_FLAG_TTY = 0x00000002

# Failure thresholds from tally.h
MAX_FAILURE = 3
FAIL_INTERVAL = 900  # 15 minutes in seconds
UNLOCK_TIME = 900    # 15 minutes in seconds

# Struct format for ptn_tally_t structure
# typedef struct {
#     char source[NAME_MAX];  // PAM_RHOST or PAM_TTY
#     uint32_t flags;         // flags related to entry
# } ptn_tally_t;
TALLY_STRUCT = (
    f"{NAME_MAX}s"  # char source[NAME_MAX]
    "I"             # uint32_t flags
)


@dataclass
class FaillogEntry:
    """Represents a single failure log entry"""
    timestamp: datetime
    source: str
    source_type: str  # "RHOST" or "TTY"
    username: str

    def __str__(self) -> str:
        """String representation of the faillog entry"""
        return (f"[{self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
                f"User: {self.username}, "
                f"{self.source_type}: {self.source}")


class PamFaillog:
    """Iterator for PAM faillog entries in the kernel keyring"""

    def __init__(self):
        """Initialize the faillog iterator"""
        self.pam_keyring = None
        self._load_keyring()

    def _load_keyring(self) -> None:
        """Load the PAM_TRUENAS keyring"""
        # Get the persistent keyring
        persistent = truenas_keyring.get_persistent_keyring()
        # Search for the PAM_TRUENAS keyring within it
        self.pam_keyring = persistent.search(
            key_type="keyring",
            description=PAM_KEYRING_NAME
        )

    def parse_entry(self, key_data: bytes, username: str, key_description: str) -> FaillogEntry:
        """
        Parse a faillog entry from raw key data

        Args:
            key_data: Raw bytes from the keyring
            username: Username associated with this faillog
            key_description: Key description (timestamp as string)

        Returns:
            FaillogEntry object

        Raises:
            ValueError: If the entry cannot be parsed
        """
        # Unpack the tally structure
        unpacked = struct.unpack(TALLY_STRUCT, key_data)

        # Extract fields
        source = unpacked[0].rstrip(b'\x00').decode('utf-8')
        flags = unpacked[1]

        # Determine source type based on flags
        if flags & TALLY_FLAG_RHOST:
            source_type = "RHOST"
        elif flags & TALLY_FLAG_TTY:
            source_type = "TTY"
        else:
            source_type = "UNKNOWN"

        # Parse timestamp from key description
        timestamp = datetime.fromtimestamp(float(key_description))

        return FaillogEntry(
            timestamp=timestamp,
            source=source,
            source_type=source_type,
            username=username
        )

    def iterate(self) -> Iterator[FaillogEntry]:
        """
        Iterate over all faillog entries in the kernel keyring

        Yields:
            FaillogEntry objects for each failure in the keyring
        """
        if self.pam_keyring is None:
            return

        # Structure: PAM_TRUENAS -> username -> FAILLOG -> failure_keys
        # Iterate through all username keyrings under PAM_TRUENAS
        for user_item in self.pam_keyring.iter_keyring_contents(
            unlink_revoked=True,
            unlink_expired=True
        ):
            # Get the username from the keyring description
            username = user_item.key.description
            user_keyring = user_item

            try:
                # Look for the FAILLOG keyring under this user
                faillog_keyring = user_keyring.search(
                    key_type="keyring",
                    description=PAM_FAILLOG_NAME
                )
            except FileNotFoundError:
                # No FAILLOG keyring for this user
                continue

            # Iterate through the failure entries in the FAILLOG keyring
            for failure_key in faillog_keyring.iter_keyring_contents(
                unlink_revoked=True,
                unlink_expired=True
            ):
                # TNKey objects are returned directly from faillog iteration
                # Only process user keys (actual faillog data)
                if not hasattr(failure_key, 'key_type') or failure_key.key_type != 'user':
                    continue

                # Read the key data
                key_data = failure_key.read_data()
                if key_data:
                    yield self.parse_entry(
                        key_data,
                        username,
                        failure_key.description
                    )

    def __get_user_keyring(self, username: str):
        if not self.pam_keyring:
            self._load_keyring()

        try:
            user_keyring = self.pam_keyring.search(
                key_type=truenas_keyring.KeyType.KEYRING,
                description=username
            )
        except FileNotFoundError:
            return None
        except PermissionError:
            # persistent keyring may not be initialized in current thread
            self._load_keyring()
            try:
                user_keyring = self.pam_keyring.search(
                    key_type=truenas_keyring.KeyType.KEYRING,
                    description=username
                )
            except FileNotFoundError:
                return None

        return user_keyring

    def __get_failure_keyring(self, user_keyring):
        try:
            faillog_keyring = user_keyring.search(
                key_type=truenas_keyring.KeyType.KEYRING,
                description=PAM_FAILLOG_NAME
            )
        except FileNotFoundError:
            # truenas_pykeyring converts ENOKEY to FileNotFoundError
            faillog_keyring = None

        return faillog_keyring

    def __get_lock_key(self, user_keyring):
        try:
            lock_key = user_keyring.search(
                key_type=truenas_keyring.KeyType.USER,
                description=PAM_TALLY_LOCK_NAME
            )
        except FileNotFoundError:
            # truenas_pykeyring converts ENOKEY to FileNotFoundError
            return None
        except truenas_keyring.KeyringError as exc:
            if exc.errno == errno.EKEYEXPIRED or exc.errno == errno.EKEYREVOKED:
                # Forcing cpython extension iterate keyring contents forces deletion
                # of expired lock
                user_keyring.list_keyring_contents()
                return None

            raise

        return lock_key

    def get_user_failures(self, username: str) -> list[FaillogEntry]:
        """
        Get all failure entries for a specific user

        Args:
            username: Username to query

        Returns:
            List of FaillogEntry objects for the user
        """
        entries = []
        if (user_keyring := self.__get_user_keyring(username)) is None:
            return entries

        if (failures := self.__get_failure_keyring(user_keyring)) is None:
            return entries

        for fail_entry in failures.iter_keyring_contents(
            unlink_revoked=True,
            unlink_expired=True
        ):
            key_data = fail_entry.read_data()
            entry = self.parse_entry(key_data, username, fail_entry.description)
            entries.append(entry)

        return entries

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about current faillog entries

        Returns:
            Dictionary with statistics about failures
        """
        stats = {
            'total_failures': 0,
            'locked_users': [],
            'users_with_failures': {},
            'failures_by_source_type': {'RHOST': 0, 'TTY': 0, 'UNKNOWN': 0}
        }

        user_failures = {}

        for entry in self.iterate():
            stats['total_failures'] += 1
            stats['failures_by_source_type'][entry.source_type] += 1

            if entry.username not in user_failures:
                user_failures[entry.username] = []
            user_failures[entry.username].append(entry)

        # Check which users are locked
        now = datetime.now()
        for username, failures in user_failures.items():
            # Count recent failures (within FAIL_INTERVAL)
            recent_failures = [
                f for f in failures
                if (now - f.timestamp).total_seconds() <= FAIL_INTERVAL
            ]

            stats['users_with_failures'][username] = len(recent_failures)

            if len(recent_failures) >= MAX_FAILURE:
                stats['locked_users'].append(username)

        return stats

    def is_tally_locked(self, username: str) -> bool:
        """ This function checks for whether the pam_truenas user keyring has a tally_lock key set on it. """
        if (user_keyring := self.__get_user_keyring(username)) is None:
            # No user keyring / session info. It's not possible for it to be tally locked.
            return False

        lock_key = self.__get_lock_key(user_keyring)
        return lock_key is not None

    def reset_tally(self, username: str) -> None:
        """ Reset FAILLOG for the specified username and remove its tally-lock """
        if (user_keyring := self.__get_user_keyring(username)) is None:
            # No user keyring / session info. It's not possible for it to be tally locked.
            return None

        if (failure_keyring := self.__get_failure_keyring(user_keyring)) is not None:
            # Wipe all failed login attempts from log
            failure_keyring.clear()

        # There is a separate key thats presence indicates the user is
        # tally locked. Remove this as well if it exists.
        if (lock_key := self.__get_lock_key(user_keyring)) is None:
            return

        # Unlink the locking key from the user keyring.
        user_keyring.unlink_key(lock_key.serial)

    def tally_locked_users(self) -> set[str]:
        """ Create a set of usernames of all users who are currently tally locked. The
        TRUENAS_PAM_KEYRING key descriptions contain the affected user's name. """
        locked_users = set()
        if not self.pam_keyring:
            self._load_keyring()

        try:
            pam_iter = self.pam_keyring.iter_keyring_contents(
                unlink_revoked=True,
                unlink_expired=True
            )
        except PermissionError:
            self._load_keyring()
            pam_iter = self.pam_keyring.iter_keyring_contents(
                unlink_revoked=True,
                unlink_expired=True
            )

        for user_keyring in pam_iter:
            try:
                if self.__get_lock_key(user_keyring):
                    locked_users.add(user_keyring.key.description)
            except Exception:
                # This is called in user.query extend context. We can't allow exceptions or logs to be raised here
                # because the code path is really hot.
                pass

        return locked_users
