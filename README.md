# PAM TrueNAS

PAM module for TrueNAS providing SCRAM-SHA-512 authentication, session management, and brute-force protection using the Linux kernel keyring.

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
auth    [success=1 default=ignore]    pam_truenas.so debug
auth    [default=done]                pam_truenas.so authfail
auth    required                      pam_truenas.so authsucc

# Account management (use other module or permit)
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
- Thread-safe keyring storage

Failure entries stored in FAILLOG keyring:
- Key description: Unix timestamp
- Key data: `ptn_tally_t` struct (defined in `src/tally.h`)
- Key timeout: 900 seconds (auto-expiry)

Session entries stored in SESSIONS keyring:
- Key description: Session UUID
- Key data: `kr_sess_t` struct (defined in `src/kr_session.h`)
- Key lifetime: Tied to process lifetime

## Python Libraries

Python libraries are provided to manage the faillog and read session state:
- `truenas_pam_session` - Read and iterate PAM sessions from kernel keyring
- `truenas_pam_faillog` - Read and iterate authentication failure logs

See the Python module docstrings for API documentation.

## Environment Variables

When `use_env_config` is enabled:

- `pam_truenas_password_auth=1` - Enable password auth
- `pam_truenas_password_auth_is_api_key=1` - Password is API key
- `pam_truenas_session_uuid` - Session UUID for tracking
- `pam_truenas_session_data` - JSON session metadata

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
- API keys not provisioned by middleware
- Run middleware API key setup

**"API key expired"**
- Key has expiration timestamp in past
- Regenerate through TrueNAS interface

**"Session limit exceeded"**
- User at max_sessions limit
- Check active sessions with Python libraries
- Old processes may not have cleaned up

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
