"""libpam driven directly, the way C applications use it

truenas_pypam only closes a session on the handle that opened it. Samba opens
and closes each SMB session on its own handle (smb_pam_claim_session() /
smb_pam_close_session()), so tests of that pattern use these helpers.
"""

import contextlib
import ctypes
import ctypes.util
import json
import os
import tempfile

PAM_SUCCESS = 0
PAM_PERM_DENIED = 6
PAM_CONV_ERR = 19
PAM_TTY = 3
PAM_RHOST = 4
PAM_DELETE_CRED = 0x0004
PAM_SILENT = 0x8000

_CONV_FUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
                              ctypes.c_void_p, ctypes.c_void_p)


class _PamConv(ctypes.Structure):
    _fields_ = [("conv", _CONV_FUNC), ("appdata_ptr", ctypes.c_void_p)]


@_CONV_FUNC
def _no_conversation(num_msg, msg, resp, appdata_ptr):
    return PAM_CONV_ERR


_CONV = _PamConv(_no_conversation, None)

_libpam = ctypes.CDLL(ctypes.util.find_library("pam"))
_libpam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.POINTER(_PamConv), ctypes.POINTER(ctypes.c_void_p)]
_libpam.pam_set_item.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_char_p]
_libpam.pam_putenv.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_libpam.pam_getenv.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_libpam.pam_getenv.restype = ctypes.c_char_p
for _fn in ("pam_open_session", "pam_close_session", "pam_setcred", "pam_end"):
    getattr(_libpam, _fn).argtypes = [ctypes.c_void_p, ctypes.c_int]


def tcp_session_data(rem_port, family="AF_INET"):
    """The origin middlewared supplies for a TCP connection"""
    v6 = family == "AF_INET6"
    return {
        "origin_family": family,
        "origin": {
            "loc_addr": "::1" if v6 else "127.0.0.1",
            "loc_port": 443,
            "rem_addr": "fd00::64" if v6 else "192.168.1.100",
            "rem_port": rem_port,
            "ssl": True
        }
    }


class PamHandle:
    """A PAM handle used the way C applications use one"""

    def __init__(self, service, user, *, tty=None, rhost="192.168.1.100",
                 session_data=None):
        self.pamh = ctypes.c_void_p()
        rc = _libpam.pam_start(service.encode(), user.encode(),
                               ctypes.byref(_CONV), ctypes.byref(self.pamh))
        assert rc == PAM_SUCCESS

        _libpam.pam_set_item(self.pamh, PAM_RHOST, rhost.encode())
        if tty is not None:
            _libpam.pam_set_item(self.pamh, PAM_TTY, tty.encode())

        if session_data is not None:
            env = f"pam_truenas_session_data={json.dumps(session_data)}"
            _libpam.pam_putenv(self.pamh, env.encode())

    def open_session(self):
        return _libpam.pam_open_session(self.pamh, PAM_SILENT)

    def close_session(self):
        _libpam.pam_setcred(self.pamh, PAM_DELETE_CRED | PAM_SILENT)
        return _libpam.pam_close_session(self.pamh, PAM_SILENT)

    def getenv(self, name):
        val = _libpam.pam_getenv(self.pamh, name.encode())
        return None if val is None else val.decode()

    def end(self, status=PAM_SUCCESS):
        _libpam.pam_end(self.pamh, status)


def smb_claim_session(service, user, tty):
    """smb_pam_claim_session(): open the session on its own handle and end it"""
    handle = PamHandle(service, user, tty=tty)
    rc = handle.open_session()
    handle.end(rc)
    return rc


def smb_close_session(service, user, tty):
    """smb_pam_close_session(): close the session on a fresh handle"""
    handle = PamHandle(service, user, tty=tty)
    rc = handle.close_session()
    handle.end(rc)
    return rc


@contextlib.contextmanager
def other_smbd(service, user, tty):
    """Another process that claims an SMB session. It exits without closing
    the session when the context exits."""
    rc_r, rc_w = os.pipe()
    hold_r, hold_w = os.pipe()

    pid = os.fork()
    if pid == 0:
        try:
            os.close(rc_r)
            os.close(hold_w)
            rc = smb_claim_session(service, user, tty)
            os.write(rc_w, rc.to_bytes(4, "little"))
            os.read(hold_r, 1)
        finally:
            os._exit(0)

    os.close(rc_w)
    os.close(hold_r)
    try:
        data = os.read(rc_r, 4)
        # -1 if the child failed before reporting
        yield pid, int.from_bytes(data, "little") if len(data) == 4 else -1
    finally:
        os.close(hold_w)
        os.waitpid(pid, 0)
        os.close(rc_r)


def pam_service(session_args=""):
    """Create a temporary PAM service with pam_truenas in its session stack.
    For use as a fixture body: yields the service name."""
    fd, path = tempfile.mkstemp(dir="/etc/pam.d", prefix="test_raw_pam_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("auth    required    pam_permit.so\n"
                    "account required    pam_permit.so\n"
                    f"session required    pam_truenas.so debug {session_args}\n")
        os.chmod(path, 0o644)
        yield os.path.basename(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
