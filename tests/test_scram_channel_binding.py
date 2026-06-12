"""Tests for SCRAM channel binding (SCRAM-PLUS, RFC 5929 tls-server-end-point) via PAM.

pam_truenas reads the precomputed binding from the PAM_TRUENAS keyring by default
(the value middlewared publishes from the active TLS cert); ``scram_plus_cert=<path>``
overrides this to read+hash a PEM file. ``channel_binding=negotiate|require`` selects
the policy. These drive a real channel-bound SCRAM exchange and assert pam_truenas
enforces the binding against the client's ``c=`` per the configured source and policy.
"""
import datetime
import os
import tempfile

import pytest
import truenas_keyring
import truenas_pypam
import truenas_pyscram
from truenas_authenticator import UserPamAuthenticator

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

PAM_SERVICE = "middleware-scram-plus"
PAM_SERVICE_PATH = f"/etc/pam.d/{PAM_SERVICE}"
ECHO_OFF = truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF

# Must match PAM_SCRAM_BINDING_NAME in src/includes.h: the "user" key holding the
# precomputed binding, stored directly in the uid=0 persistent keyring.
BINDING_KEY_NAME = "TRUENAS_SCRAM_PLUS_SERVER_BINDING"


def _self_signed_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime(2026, 1, 1)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256()))


def _new_cert_and_binding():
    """Return (der, binding) for a throwaway self-signed cert."""
    der = _self_signed_cert().public_bytes(serialization.Encoding.DER)
    return der, truenas_pyscram.compute_tls_server_end_point(der)


def _set_keyring_binding(binding):
    """Publish a precomputed binding into the persistent keyring (as middlewared would)."""
    persistent = truenas_keyring.get_persistent_keyring()
    truenas_keyring.add_key(key_type=truenas_keyring.KeyType.USER,
                            description=BINDING_KEY_NAME, data=bytes(binding),
                            target_keyring=persistent.key.serial)


def _clear_keyring_binding():
    """Best-effort removal of the binding slot so tests don't leak it to each other."""
    persistent = truenas_keyring.get_persistent_keyring()
    try:
        key = persistent.search(key_type=truenas_keyring.KeyType.USER,
                                description=BINDING_KEY_NAME)
    except FileNotFoundError:
        return
    persistent.unlink_key(key.serial)


def _write_pam_service(module_args):
    with open(PAM_SERVICE_PATH, "w") as f:
        f.write(
            "auth\t[success=1 default=ignore] pam_truenas.so debug use_env_config "
            f"{module_args}\n"
            "auth\t[default=done] pam_truenas.so debug authfail\n"
            "auth\trequired pam_truenas.so debug authsucc\n"
            "auth\trequired\tpam_permit.so\n"
            "account sufficient pam_permit.so\n"
            "session required pam_truenas.so debug session_utmp\n"
            "session sufficient pam_permit.so\n"
            "@include common-password\n"
        )


@pytest.fixture(autouse=True)
def _isolate_binding():
    """Channel binding is keyring-sourced by default, so guarantee a clean slot
    around every test -- a leaked binding would silently enable CB elsewhere."""
    _clear_keyring_binding()
    yield
    _clear_keyring_binding()


@pytest.fixture(params=["negotiate", "require"])
def cb_keyring(request):
    """Keyring-sourced SCRAM-PLUS service (the production path), per policy."""
    mode = request.param
    _, binding = _new_cert_and_binding()
    _set_keyring_binding(binding)
    _write_pam_service(f"channel_binding={mode}")
    try:
        yield {"mode": mode, "binding": binding}
    finally:
        os.unlink(PAM_SERVICE_PATH)


@pytest.fixture(params=["negotiate", "require"])
def cb_file(request):
    """File-override SCRAM-PLUS service: scram_plus_cert=<path>, no keyring slot."""
    mode = request.param
    der, binding = _new_cert_and_binding()
    fd, cert_path = tempfile.mkstemp(suffix=".crt", prefix="scram_cb_")
    with os.fdopen(fd, "wb") as f:
        f.write(x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM))
    _write_pam_service(f"scram_plus_cert={cert_path} channel_binding={mode}")
    try:
        yield {"mode": mode, "binding": binding}
    finally:
        os.unlink(cert_path)
        os.unlink(PAM_SERVICE_PATH)


def _answer(reason, value):
    return [value if m.msg_style == ECHO_OFF else None for m in reason]


def _first_secret(reason):
    return next(m.msg for m in reason if m.msg_style == ECHO_OFF)


def _drive_to_final(api_key_data, *, channel_binding_type, channel_binding):
    """Run init -> client-first -> client-final; return the client-final PAMCode.

    channel_binding_type builds the gs2 'p=<type>' header via the library (None
    yields a plain 'n' client). We let truenas_pyscram format the header rather
    than hand-writing it, so the cbind-input ',,' separator is always correct. On
    success pam_truenas replies with the server-final (PAM_CONV_AGAIN); on a
    binding/proof failure it returns PAM_AUTH_ERR.
    """
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}", service=PAM_SERVICE)
    resp = auth.auth_init()
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN

    cf_kwargs = {"username": api_key_data["username"], "api_key_id": api_key_data["id"]}
    if channel_binding_type is not None:
        cf_kwargs["channel_binding_type"] = channel_binding_type
    cf = truenas_pyscram.ClientFirstMessage(**cf_kwargs)

    resp = auth.auth_continue(_answer(resp.reason, str(cf)))
    assert resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    sf = truenas_pyscram.ServerFirstMessage(rfc_string=_first_secret(resp.reason))

    ad = api_key_data["scram_auth_data"]
    cfin_kwargs = {"client_first": cf, "server_first": sf,
                   "client_key": ad.client_key, "stored_key": ad.stored_key}
    if channel_binding is not None:
        cfin_kwargs["channel_binding"] = channel_binding
    cfin = truenas_pyscram.ClientFinalMessage(**cfin_kwargs)

    resp = auth.auth_continue(_answer(resp.reason, str(cfin)))
    code = resp.code
    auth.end()
    return code


def _expect_unbound(mode):
    """An 'n' client is allowed under negotiate, rejected under require."""
    return (truenas_pypam.PAMCode.PAM_AUTH_ERR if mode == "require"
            else truenas_pypam.PAMCode.PAM_CONV_AGAIN)


# --- keyring source (default / production path) -----------------------------

def test_keyring_matching_binding(api_key_data, cb_keyring):
    """A 'p' client whose binding matches the keyring slot is verified (both modes)."""
    code = _drive_to_final(api_key_data, channel_binding_type=truenas_pyscram.CB_TLS_SERVER_END_POINT,
                           channel_binding=cb_keyring["binding"])
    assert code == truenas_pypam.PAMCode.PAM_CONV_AGAIN


def test_keyring_mismatched_binding_rejected(api_key_data, cb_keyring):
    """A 'p' client binding to a DIFFERENT cert (a re-terminating MITM) is rejected."""
    code = _drive_to_final(api_key_data, channel_binding_type=truenas_pyscram.CB_TLS_SERVER_END_POINT,
                           channel_binding=truenas_pyscram.CryptoDatum(b"\x00" * 32))
    assert code == truenas_pypam.PAMCode.PAM_AUTH_ERR


def test_keyring_unbound_client_policy(api_key_data, cb_keyring):
    """An 'n' client is allowed under negotiate, rejected under require."""
    code = _drive_to_final(api_key_data, channel_binding_type=None, channel_binding=None)
    assert code == _expect_unbound(cb_keyring["mode"])


# --- file override (scram_plus_cert=<path>) ---------------------------------

def test_file_override_matching_binding(api_key_data, cb_file):
    """The file source is used in place of the keyring when a path is given."""
    code = _drive_to_final(api_key_data, channel_binding_type=truenas_pyscram.CB_TLS_SERVER_END_POINT,
                           channel_binding=cb_file["binding"])
    assert code == truenas_pypam.PAMCode.PAM_CONV_AGAIN


def test_file_override_unbound_client_policy(api_key_data, cb_file):
    """Policy applies identically when the binding comes from a file."""
    code = _drive_to_final(api_key_data, channel_binding_type=None, channel_binding=None)
    assert code == _expect_unbound(cb_file["mode"])


# --- explicit sentinel + absent slot ----------------------------------------

def test_sentinel_selects_keyring_source(api_key_data):
    """scram_plus_cert=truenas_keyring is the explicit form of the default source."""
    _, binding = _new_cert_and_binding()
    _set_keyring_binding(binding)
    _write_pam_service("scram_plus_cert=truenas_keyring channel_binding=negotiate")
    try:
        code = _drive_to_final(api_key_data, channel_binding_type=truenas_pyscram.CB_TLS_SERVER_END_POINT,
                               channel_binding=binding)
        assert code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    finally:
        os.unlink(PAM_SERVICE_PATH)


def test_no_binding_negotiate_allows_unbound(api_key_data):
    """No keyring slot + negotiate: channel binding is off, plain SCRAM succeeds."""
    _write_pam_service("channel_binding=negotiate")
    try:
        code = _drive_to_final(api_key_data, channel_binding_type=None, channel_binding=None)
        assert code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    finally:
        os.unlink(PAM_SERVICE_PATH)


def test_no_binding_require_fails_closed(api_key_data):
    """No keyring slot + require: nothing to bind against, so authentication fails."""
    _write_pam_service("channel_binding=require")
    try:
        code = _drive_to_final(api_key_data, channel_binding_type=None, channel_binding=None)
        assert code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    finally:
        os.unlink(PAM_SERVICE_PATH)


def test_no_binding_rejects_bound_client(api_key_data):
    """No keyring slot + negotiate: a 'p' client that demands binding is rejected,
    not accepted unverified (no silent MITM window during a binding gap)."""
    _write_pam_service("channel_binding=negotiate")
    try:
        code = _drive_to_final(
            api_key_data,
            channel_binding_type=truenas_pyscram.CB_TLS_SERVER_END_POINT,
            channel_binding=truenas_pyscram.CryptoDatum(b"\x11" * 32))
        assert code == truenas_pypam.PAMCode.PAM_AUTH_ERR
    finally:
        os.unlink(PAM_SERVICE_PATH)


def test_empty_scram_plus_cert_uses_keyring(api_key_data):
    """scram_plus_cert= with no value falls back to the keyring, not a literal '' path."""
    _, binding = _new_cert_and_binding()
    _set_keyring_binding(binding)
    _write_pam_service("scram_plus_cert= channel_binding=negotiate")
    try:
        code = _drive_to_final(
            api_key_data,
            channel_binding_type=truenas_pyscram.CB_TLS_SERVER_END_POINT,
            channel_binding=binding)
        assert code == truenas_pypam.PAMCode.PAM_CONV_AGAIN
    finally:
        os.unlink(PAM_SERVICE_PATH)
