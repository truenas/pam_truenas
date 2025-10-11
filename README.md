# PAM TrueNAS

PAM module for TrueNAS providing SCRAM-SHA-512 authentication and session management.

## Features

- **SCRAM-SHA-512 Authentication**: RFC 5802 challenge-response protocol with SHA-512
- **API Key Support**: Multiple API keys per user with expiration
- **Session Tracking**: Kernel keyring-based session management with limits
- **Faillock**: STIG-compliant brute-force protection (SRG-OS-000329-GPOS-00128)

## Dependencies

### Build Dependencies

```bash
# Debian/Ubuntu
sudo apt install build-essential autoconf automake libtool pkg-config
sudo apt install libpam0g-dev libkeyutils-dev libjansson-dev uuid-dev
sudo apt install dh-python python3-all python3-setuptools python3-build python3-installer

# Install TrueNAS libraries
sudo apt install libtruenas-scram-dev libtruenas-pwenc-dev
```

### Runtime Dependencies

- Linux kernel ≥ 3.13 (persistent keyring support)
- libpam0g
- libkeyutils1
- libjansson
- libuuid1
- libtruenas-scram
- libtruenas-pwenc

## Building

### From Source

```bash
autoreconf -fiv
./configure
make
sudo make install
```

### Debian Package

```bash
# Build both packages (libpam-truenas and python3-truenas-pam-utils)
dpkg-buildpackage -us -uc -b

# Install
sudo dpkg -i ../libpam-truenas_*.deb ../python3-truenas-pam-utils_*.deb
```

## PAM Module Functions

### pam_sm_authenticate

Main authentication function supporting:
- SCRAM-SHA-512 challenge-response
- Password/API key fallback (with `allow_password_auth`)
- Faillock tally management (with `authsucc`/`authfail`)

**Options:**
- `debug` - Enable debug logging
- `debug_state` - Log internal state
- `silent` - Suppress messages
- `allow_password_auth` - Enable password fallback
- `password_is_api_key` - Parse `dbid-keymaterial` format
- `use_env_config` - Read config from PAM environment
- `authsucc` - Reset tally on success
- `authfail` - Increment tally on failure

**Basic authentication:**
```
auth    required    pam_truenas.so
```

**SCRAM with password fallback:**
```
auth    required    pam_truenas.so allow_password_auth
```

**Authentication with faillock (STIG-compliant):**
```
# Main auth (skip authfail on success)
auth    [success=1 default=ignore]    pam_truenas.so

# Record failure
auth    [default=done]                pam_truenas.so authfail

# Check tally and reset on success
auth    required                      pam_truenas.so authsucc
```

### pam_sm_open_session / pam_sm_close_session

Session tracking in kernel keyring with optional per-user limits.

**Options:**
- `max_sessions=N` - Limit user to N concurrent sessions

**Configuration:**
```
session required    pam_truenas.so max_sessions=10
```

### pam_sm_setcred

Stub function, returns `PAM_IGNORE`.

### pam_sm_acct_mgmt

Not implemented, returns `PAM_IGNORE`.

### pam_sm_chauthtok

Not implemented, returns `PAM_IGNORE`.

## Complete PAM Configuration Example

```
# Authentication with faillock
auth    [success=2 default=ignore]    pam_unix.so
auth    [success=1 default=ignore]    pam_truenas.so
auth    [default=done]                pam_truenas.so authfail
auth    required                      pam_truenas.so authsucc
auth    required                      pam_permit.so

# Account management (use other module or permit)
account [success=1 new_authtok_reqd=done default=ignore]        pam_unix.so
account requisite                     pam_deny.so
account required                      pam_permit.so

# Session management with limits
session required                      pam_truenas.so max_sessions=10
```

## Authentication Format

API keys are identified by database ID:

- `username` - Uses dbid 0 (reserved for user account SCRAM auth, not currently implemented)
- `username:1` - Uses API key with dbid 1
- `username:2` - Uses API key with dbid 2

Keys are stored encrypted in the kernel keyring hierarchy:
```
persistent-keyring:uid=0
└── PAM_TRUENAS
    └── username
        ├── API_KEYS
        │   ├── 0 (reserved for user password SCRAM auth)
        │   ├── 1 (API key)
        │   └── 2 (API key)
        ├── SESSIONS
        │   └── <uuid> (contains kr_sess_t struct)
        └── FAILLOG
            └── <timestamp> (contains ptn_tally_t struct)
```

## Faillock (Tally) Behavior

Implements SRG-OS-000329-GPOS-00128:
- Lock after **3 failures** within **15 minutes**
- Automatic unlock after **15 minutes**
- Per-source tracking (RHOST or TTY)

Failure entries stored in FAILLOG keyring:
- Key description: Unix timestamp
- Key data: `ptn_tally_t` struct (defined in `src/tally.h`)
- Key timeout: 900 seconds (auto-expiry)

Session entries stored in SESSIONS keyring:
- Key description: Session UUID
- Key data: `kr_sess_t` struct (defined in `src/kr_session.h`)
- Key lifetime: Tied to process lifetime

## Python Libraries

Python libraries are provided to manage the faillog and read session state. These libraries are packaged separately as `python3-truenas-pam-utils` and require the `truenas-keyring` library.

### truenas_pam_session

Read and iterate PAM sessions stored in the kernel keyring by pam_truenas.

**Installation:**
```bash
sudo apt install python3-truenas-pam-utils
```

**Key Classes:**

- `PamSession` - Dataclass representing a PAM session with:
  - `session_id` (UUID) - Unique session identifier
  - `creation` (datetime) - Session creation time
  - `username`, `uid`, `gid` - User credentials
  - `pid`, `sid` - Process and session IDs
  - `service`, `rhost`, `ruser`, `tty` - PAM items
  - `origin_family` - Origin type: "AF_UNIX", "AF_INET", "AF_INET6"
  - `origin` - Origin details (PamUnixOrigin or PamTcpOrigin)
  - `extra_data` - Additional JSON metadata

- `PamUnixOrigin` - Unix socket connection details:
  - `pid`, `uid`, `gid`, `loginuid` - Peer process credentials
  - `security_label` - LSM label

- `PamTcpOrigin` - TCP/IP connection details:
  - `local_addr`, `local_port` - Local endpoint
  - `remote_addr`, `remote_port` - Remote endpoint
  - `ssl` - Whether HTTPS was used

- `SessionIterator` - Iterator for querying sessions:
  - `iterate()` - Yield all sessions
  - `get_sessions()` - Return list of all sessions
  - `get_session_by_id(uuid)` - Find session by UUID
  - `get_sessions_by_username(name)` - Get all sessions for user

**Usage Examples:**

```python
from truenas_pam_session import SessionIterator

# Get all sessions
iterator = SessionIterator()
for session in iterator.iterate():
    print(f"{session.username}: {session.session_id}")

# Get sessions for specific user
sessions = iterator.get_sessions_by_username("admin")
print(f"User has {len(sessions)} active sessions")

# Find session by UUID
session = iterator.get_session_by_id("550e8400-e29b-41d4-a716-446655440000")
if session:
    print(f"Session from {session.rhost} via {session.service}")
```

**Convenience Functions:**

```python
# Module-level convenience functions (create iterator internally)
from truenas_pam_session import (
    get_sessions,           # Get all sessions as list
    iterate_sessions,       # Iterate over all sessions
    get_session_by_id,      # Find by UUID
    get_sessions_by_username # Get user's sessions
)
```

### truenas_pam_faillog

Read and iterate authentication failure log entries from the kernel keyring.

**Key Classes:**

- `FaillogEntry` - Dataclass representing a failure:
  - `timestamp` (datetime) - When failure occurred
  - `source` - Remote host or TTY
  - `source_type` - "RHOST", "TTY", or "UNKNOWN"
  - `username` - User that failed authentication

- `FaillogIterator` - Iterator for querying failures:
  - `iterate()` - Yield all failure entries
  - `get_user_failures(username)` - Get failures for specific user
  - `get_statistics()` - Get statistics about failures and locked users

**Usage Examples:**

```python
from truenas_pam_faillog import FaillogIterator

# List all failures
iterator = FaillogIterator()
for entry in iterator.iterate():
    print(entry)  # Formatted as: [timestamp] User: username, RHOST: source

# Get failures for specific user
failures = iterator.get_user_failures("admin")
print(f"User has {len(failures)} recent failures")

# Get statistics
stats = iterator.get_statistics()
print(f"Total failures: {stats['total_failures']}")
print(f"Locked users: {stats['locked_users']}")
print(f"RHOST failures: {stats['failures_by_source_type']['RHOST']}")
print(f"TTY failures: {stats['failures_by_source_type']['TTY']}")
```

**Statistics Output:**

```python
{
    'total_failures': 15,
    'locked_users': ['admin', 'testuser'],
    'users_with_failures': {
        'admin': 5,      # Recent failures (within 15 min)
        'testuser': 3
    },
    'failures_by_source_type': {
        'RHOST': 12,
        'TTY': 3,
        'UNKNOWN': 0
    }
}
```

**Constants:**

- `MAX_FAILURE = 3` - Failures before account lock
- `FAIL_INTERVAL = 900` - Time window (15 minutes)
- `UNLOCK_TIME = 900` - Auto-unlock time (15 minutes)

## Environment Variables

When `use_env_config` is enabled:

- `pam_truenas_password_auth=1` - Enable password auth
- `pam_truenas_password_auth_is_api_key=1` - Password is API key
- `pam_truenas_session_uuid` - Session UUID for tracking
- `pam_truenas_session_data` - JSON session metadata

### `pam_truenas_session_uuid`

The session UUID pam environmental variable (`pam_truenas_session_uuid`) is set
by the PAM service module when `pam_open_session()` is called by the PAM
application.

### `pam_truenas_session_data`

The PAM application may use the `pam_truenas_session_data` environmental
variable to set specify additional information about the originating
session prior to calling `pam_open_session()`. This provides additional
metadata about the session's origin beyond what is normally covered
by the items `PAM_RHOST`, `PAM_RUSER`.

It is not mandatory for PAM applications to populate this data, and
consumers of session python APIs or the keyring entries should allow
for the possibility that they have not been set.

The expected data format is a JSON object containing minmally two fields:

- `"origin_family"`: one of `"AF_UNIX"`, `"AF_INET"`, or `"AF_INET6"`.
- `"origin"`: a JSON object containing on of the following origin objects.

NOTE: additional fields will be preserved and stored in a JSON object
in `json_data` in `kr_sess_t`.

This is presented through the `extra_data` field in the `PamSession`
dataclass.

#### `AF_UNIX` origin

An `AF_UNIX` origin contains the following fields based on `SO_PEERCRED`
- `"uid"` - The uid of the peer process credentials for socket connection.
- `"gid"` - The gid of the peer process credentials for socket connection.
- `"pid"` - The process ID of the peer process credentials for socket connection.
- `"loginuid"` - The loginuid of the peer process.
- `"sec"` - The LSM label for the peer process.

#### `AF_INET` and `AF_INET6`

`AF_INET` and `AF_INET6` origins contain the same fields.
- `"loc_addr"` - The local IP address associated with the TCP/IP connection.
- `"loc_port"` - The local port associated with the TCP/IP connection.
- `"rem_addr"` - The remote IP address associated with the TCP/IP connection.
- `"rem_port"` - The remote port associated with the TCP/IP connection.
- `"ssl"` - boolean field indicating whether https was used for connection

### Sample data

`AF_UNIX` origin

``` javascript
{
  "origin_family": "AF_UNIX",
  "origin": {
    "uid": 1000,
    "gid": 1000,
    "pid": 8675309,
    "loginuid": 1000,
    "sec": "webshare"
  }
}
```

`AF_INET` origin

``` javascript
{
  "origin_family: "AF_INET",
  "origin": {
    "loc_addr": "192.168.1.200,
    "loc_port": 53693,
    "rem_addr": "192.168.1.201,
    "rem_port": 53643,
    "ssl": true
  }
}
```

## Troubleshooting

### Enable Debug Logging

```
auth    required    pam_truenas.so debug
```

Logs to syslog (`/var/log/auth.log` or `/var/log/secure`).

### Inspect Keyring

```bash
# View keyring hierarchy
sudo keyctl show

# Find PAM_TRUENAS keyring
sudo keyctl search @u keyring PAM_TRUENAS

# List user's keys
KEYRING_ID=$(sudo keyctl search @u keyring PAM_TRUENAS)
sudo keyctl show $KEYRING_ID
```

### Common Errors

**"Failed to find keyring 'PAM_TRUENAS'"**
- Run middleware API key setup

**"API key expired"**
- Key has expiration timestamp in past
- Regenerate through TrueNAS interface

**"Session limit exceeded"**
- User at `max_sessions` limit
- Check active sessions with Python libraries

## License

LGPL-3.0-or-later

Copyright © 2025 iXsystems, Inc., DBA TrueNAS

## Related Projects

- [truenas_scram](https://github.com/truenas/truenas_scram) - SCRAM-SHA-512 implementation
- [truenas_pwenc](https://github.com/truenas/truenas_pwenc) - TrueNAS pwenc library
- [truenas_pypam](https://github.com/truenas/truenas_pypam) - Python PAM bindings
- [truenas_pykeyring](https://github.com/truenas/truenas_pykeyring) - Python kernel keyring interface

## References

- [RFC 5802](https://www.rfc-editor.org/rfc/rfc5802.html) - SCRAM protocol
- [STIG SRG-OS-000329-GPOS-00128](https://www.stigviewer.com/stig/general_purpose_operating_system_srg/) - Account lockout requirements
- [keyutils(7)](https://man7.org/linux/man-pages/man7/keyutils.7.html) - Linux kernel keyring
- [pam(8)](https://man7.org/linux/man-pages/man8/pam.8.html) - Pluggable Authentication Modules
