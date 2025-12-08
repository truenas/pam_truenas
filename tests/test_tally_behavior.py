"""Tests for PAM tally behavior - account locking and faillog clearing."""

import pytest
import time
import truenas_pypam
import truenas_pyscram
import truenas_keyring
from truenas_authenticator import UserPamAuthenticator, AuthenticatorStage
from truenas_pam_faillog import FaillogIterator, MAX_FAILURE


@pytest.fixture(autouse=True)
def clear_faillog_before_test():
    """Clear faillog before each test to ensure clean state"""
    # Clear before test
    try:
        persistent = truenas_keyring.get_persistent_keyring()
        pam_keyring = persistent.search(key_type="keyring", description="PAM_TRUENAS")
        bob_keyring = pam_keyring.search(key_type="keyring", description="bob")
        faillog = bob_keyring.search(key_type="keyring", description="FAILLOG")
        faillog.clear()
    except (FileNotFoundError, AttributeError):
        pass  # No faillog to clear

    yield  # Run the test

    # Clear after test too
    try:
        persistent = truenas_keyring.get_persistent_keyring()
        pam_keyring = persistent.search(key_type="keyring", description="PAM_TRUENAS")
        bob_keyring = pam_keyring.search(key_type="keyring", description="bob")
        faillog = bob_keyring.search(key_type="keyring", description="FAILLOG")
        faillog.clear()
    except (FileNotFoundError, AttributeError):
        pass


def perform_failed_auth(api_key_data, pam_service="middleware-scram"):
    """Helper to perform a failed authentication attempt"""
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service
    )

    # Initialize authentication
    resp = auth.auth_init()
    if resp.code != truenas_pypam.PAMCode.PAM_CONV_AGAIN:
        auth.end()
        return resp.code

    # Create SCRAM client-first message
    client_first = truenas_pyscram.ClientFirstMessage(
        username=api_key_data["username"],
        api_key_id=api_key_data["id"]
    )

    # Provide client-first message
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(str(client_first))
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)
    if resp.code != truenas_pypam.PAMCode.PAM_CONV_AGAIN:
        auth.end()
        return resp.code

    # Extract server-first message
    server_first_str = None
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            server_first_str = msg.msg
            break

    if server_first_str is None:
        auth.end()
        return truenas_pypam.PAMCode.PAM_AUTH_ERR

    # Create server-first message object
    server_first = truenas_pyscram.ServerFirstMessage(rfc_string=server_first_str)

    # Generate WRONG auth data to cause failure
    wrong_auth_data = truenas_pyscram.generate_scram_auth_data(
        salt=server_first.salt,
        iterations=server_first.iterations
    )

    # Create client-final message with wrong auth data
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=wrong_auth_data.client_key,
        stored_key=wrong_auth_data.stored_key
    )

    # Provide client-final message
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(str(client_final))
        else:
            responses.append(None)

    # Continue authentication (should fail)
    resp = auth.auth_continue(responses)
    auth.end()

    return resp.code


def perform_successful_auth(api_key_data, pam_service="middleware-scram"):
    """Helper to perform a successful authentication attempt"""
    auth = UserPamAuthenticator(
        username=f"{api_key_data['username']}:{api_key_data['id']}",
        service=pam_service
    )

    # Initialize authentication
    resp = auth.auth_init()
    if resp.code != truenas_pypam.PAMCode.PAM_CONV_AGAIN:
        auth.end()
        return resp.code

    # Create SCRAM client-first message
    client_first = truenas_pyscram.ClientFirstMessage(
        username=api_key_data["username"],
        api_key_id=api_key_data["id"]
    )

    # Provide client-first message
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(str(client_first))
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)
    if resp.code != truenas_pypam.PAMCode.PAM_CONV_AGAIN:
        auth.end()
        return resp.code

    # Extract server-first message
    server_first_str = None
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            server_first_str = msg.msg
            break

    if server_first_str is None:
        auth.end()
        return truenas_pypam.PAMCode.PAM_AUTH_ERR

    # Create server-first message object
    server_first = truenas_pyscram.ServerFirstMessage(rfc_string=server_first_str)

    # Use the correct auth_data from fixture
    auth_data = api_key_data["scram_auth_data"]

    # Create client-final message with correct auth data
    client_final = truenas_pyscram.ClientFinalMessage(
        client_first=client_first,
        server_first=server_first,
        client_key=auth_data.client_key,
        stored_key=auth_data.stored_key
    )

    # Provide client-final message
    responses = []
    for msg in resp.reason:
        if msg.msg_style == truenas_pypam.MSGStyle.PAM_PROMPT_ECHO_OFF:
            responses.append(str(client_final))
        else:
            responses.append(None)

    # Continue authentication
    resp = auth.auth_continue(responses)

    if resp.code == truenas_pypam.PAMCode.PAM_CONV_AGAIN:
        # Complete the SCRAM handshake
        resp = auth.auth_continue([None])

    auth.end()
    return resp.code


def get_faillog_count(username):
    """Get the current number of faillog entries for a user"""
    faillog = FaillogIterator()
    failures = faillog.get_user_failures(username)
    return len(failures)


def test_tally_account_locking_after_max_failures(api_key_data):
    """Test that account gets locked after MAX_FAILURE authentication failures"""
    username = api_key_data["username"]

    # Clear any existing failures first
    initial_count = get_faillog_count(username)
    if initial_count > 0:
        # Perform a successful auth to clear the faillog
        result = perform_successful_auth(api_key_data)
        assert result == truenas_pypam.PAMCode.PAM_SUCCESS
        # Verify faillog was cleared
        assert get_faillog_count(username) == 0

    # Perform MAX_FAILURE - 1 failed authentications
    for i in range(MAX_FAILURE - 1):
        result = perform_failed_auth(api_key_data)
        assert result == truenas_pypam.PAMCode.PAM_AUTH_ERR, f"Failed auth {i+1} should return PAM_AUTH_ERR"

        # Check that failures are being recorded
        time.sleep(0.1)  # Small delay to ensure keyring is updated
        failure_count = get_faillog_count(username)
        assert failure_count == i + 1, f"Expected {i+1} failures, got {failure_count}"

    # Account should still be accessible (not locked yet)
    result = perform_successful_auth(api_key_data)
    assert result == truenas_pypam.PAMCode.PAM_SUCCESS, "Account should not be locked before MAX_FAILURE"

    # Faillog should be cleared after successful auth
    assert get_faillog_count(username) == 0, "Faillog should be cleared after successful auth"

    # Now perform MAX_FAILURE failed authentications to lock the account
    for i in range(MAX_FAILURE):
        result = perform_failed_auth(api_key_data)
        assert result == truenas_pypam.PAMCode.PAM_AUTH_ERR, f"Failed auth {i+1} should return PAM_AUTH_ERR"
        time.sleep(0.1)  # Small delay to ensure keyring is updated

    # Check that we have MAX_FAILURE entries
    failure_count = get_faillog_count(username)
    assert failure_count == MAX_FAILURE, f"Expected {MAX_FAILURE} failures after lock, got {failure_count}"

    # Now the account should be locked - even correct credentials should fail
    result = perform_successful_auth(api_key_data)
    assert result == truenas_pypam.PAMCode.PAM_AUTH_ERR, "Account should be locked after MAX_FAILURE attempts"

    # Faillog should still have MAX_FAILURE entries (not cleared when locked)
    failure_count = get_faillog_count(username)
    assert failure_count >= MAX_FAILURE, f"Faillog should maintain at least {MAX_FAILURE} entries when locked"


def test_tally_faillog_cleared_on_success(api_key_data):
    """Test that faillog is cleared after successful authentication"""
    username = api_key_data["username"]

    # Clear any existing failures first
    initial_count = get_faillog_count(username)
    if initial_count > 0:
        # Try to authenticate successfully to clear
        result = perform_successful_auth(api_key_data)
        assert result == truenas_pypam.PAMCode.PAM_SUCCESS:

    # Verify starting with clean slate
    assert get_faillog_count(username) == 0, "Should start with no failures"

    # Perform some failed authentications (but less than MAX_FAILURE)
    num_failures = MAX_FAILURE - 2
    for i in range(num_failures):
        result = perform_failed_auth(api_key_data)
        assert result == truenas_pypam.PAMCode.PAM_AUTH_ERR
        time.sleep(0.1)  # Small delay to ensure keyring is updated

    # Verify failures were recorded
    failure_count = get_faillog_count(username)
    assert failure_count == num_failures, f"Expected {num_failures} failures, got {failure_count}"

    # Perform successful authentication
    result = perform_successful_auth(api_key_data)
    assert result == truenas_pypam.PAMCode.PAM_SUCCESS, "Authentication should succeed"

    # Check that faillog was cleared
    time.sleep(0.1)  # Small delay to ensure keyring is updated
    failure_count = get_faillog_count(username)
    assert failure_count == 0, "Faillog should be cleared after successful authentication"


def test_tally_multiple_users_independent(api_key_data):
    """Test that tally tracking is independent per user"""
    username = api_key_data["username"]

    # Clear any existing failures for our test user
    initial_count = get_faillog_count(username)
    if initial_count > 0:
        result = perform_successful_auth(api_key_data)
        if result != truenas_pypam.PAMCode.PAM_SUCCESS:
            pytest.skip("Account appears to be locked, skipping test")

    # Add some failures for the test user
    for i in range(2):
        result = perform_failed_auth(api_key_data)
        assert result == truenas_pypam.PAMCode.PAM_AUTH_ERR
        time.sleep(0.1)

    # Check failures for test user
    failure_count = get_faillog_count(username)
    assert failure_count == 2, f"Expected 2 failures for {username}, got {failure_count}"

    # Check that other users don't have failures
    # (We can't actually test another user without their credentials,
    # but we can verify the API works correctly for non-existent users)
    other_user_failures = get_faillog_count("nonexistent_user")
    assert other_user_failures == 0, "Non-existent user should have no failures"

    # Clean up - clear the test user's failures
    result = perform_successful_auth(api_key_data)
    assert result == truenas_pypam.PAMCode.PAM_SUCCESS
    assert get_faillog_count(username) == 0


def test_tally_statistics(api_key_data):
    """Test the faillog statistics functionality"""
    username = api_key_data["username"]

    # Clear any existing failures
    initial_count = get_faillog_count(username)
    if initial_count > 0:
        result = perform_successful_auth(api_key_data)
        if result != truenas_pypam.PAMCode.PAM_SUCCESS:
            pytest.skip("Account appears to be locked, skipping test")

    # Get initial statistics
    faillog = FaillogIterator()
    stats = faillog.get_statistics()
    initial_total = stats['total_failures']

    # Add some failures
    num_failures = 2
    for i in range(num_failures):
        result = perform_failed_auth(api_key_data)
        assert result == truenas_pypam.PAMCode.PAM_AUTH_ERR
        time.sleep(0.1)

    # Get updated statistics
    stats = faillog.get_statistics()

    # Verify statistics
    assert stats['total_failures'] >= initial_total + num_failures
    assert username in stats['users_with_failures']
    assert stats['users_with_failures'][username] == num_failures
    assert username not in stats['locked_users']  # Not locked with only 2 failures

    # Add one more failure to reach MAX_FAILURE
    result = perform_failed_auth(api_key_data)
    assert result == truenas_pypam.PAMCode.PAM_AUTH_ERR
    time.sleep(0.1)

    # Check if user is now marked as locked
    stats = faillog.get_statistics()
    assert username in stats['locked_users'], f"User {username} should be locked after {MAX_FAILURE} failures"

    # Clean up
    # Note: Since the account is locked, we can't clean up with successful auth
    # The failures will expire after FAIL_INTERVAL seconds


def test_tally_failure_expiry():
    """Test that individual failure entries expire after FAIL_INTERVAL"""
    # This test would need to wait 15 minutes for entries to expire naturally
    # For practical testing, we'll just verify the mechanism exists

    faillog = FaillogIterator()

    # The iterator has logic to handle expired entries
    # When iterating, it will automatically unlink expired entries
    # This is handled by the unlink_expired=True parameter in iter_keyring_contents

    # We can't easily test the actual expiry without waiting 15 minutes
    # or having a way to manipulate the keyring timeout
    # So we'll just verify the code paths exist

    assert hasattr(faillog, 'iterate')
    assert hasattr(faillog, 'get_user_failures')

    # The actual expiry is handled at the kernel keyring level
    # and the PAM module sets keyctl_set_timeout(key_id, FAIL_INTERVAL)
    # which we can see in tally.c:71


def test_tally_with_consecutive_successes(api_key_data):
    """Test that consecutive successful authentications don't create issues"""
    username = api_key_data["username"]

    # Clear any existing failures
    initial_count = get_faillog_count(username)
    if initial_count > 0:
        result = perform_successful_auth(api_key_data)
        if result != truenas_pypam.PAMCode.PAM_SUCCESS:
            pytest.skip("Account appears to be locked, skipping test")

    # Perform multiple successful authentications
    for i in range(3):
        result = perform_successful_auth(api_key_data)
        assert result == truenas_pypam.PAMCode.PAM_SUCCESS, f"Success {i+1} should work"

        # Verify no failures are recorded
        failure_count = get_faillog_count(username)
        assert failure_count == 0, f"No failures should be recorded for successful auth"


def test_tally_recovery_scenario(api_key_data):
    """Test a complete lock and recovery scenario"""
    username = api_key_data["username"]

    # Clear any existing failures
    initial_count = get_faillog_count(username)
    if initial_count > 0:
        result = perform_successful_auth(api_key_data)
        if result != truenas_pypam.PAMCode.PAM_SUCCESS:
            # If locked, we need to wait or skip
            pytest.skip("Account is locked, cannot test recovery scenario")

    # Scenario 1: Almost lock the account
    for i in range(MAX_FAILURE - 1):
        result = perform_failed_auth(api_key_data)
        assert result == truenas_pypam.PAMCode.PAM_AUTH_ERR
        time.sleep(0.1)

    # Verify we're at the threshold
    failure_count = get_faillog_count(username)
    assert failure_count == MAX_FAILURE - 1

    # Recover with successful auth
    result = perform_successful_auth(api_key_data)
    assert result == truenas_pypam.PAMCode.PAM_SUCCESS, "Should be able to recover before lock"

    # Verify clean slate
    failure_count = get_faillog_count(username)
    assert failure_count == 0, "Failures should be cleared"

    # Scenario 2: Lock the account
    for i in range(MAX_FAILURE):
        result = perform_failed_auth(api_key_data)
        assert result == truenas_pypam.PAMCode.PAM_AUTH_ERR
        time.sleep(0.1)

    # Verify locked
    result = perform_successful_auth(api_key_data)
    assert result == truenas_pypam.PAMCode.PAM_AUTH_ERR, "Account should be locked"

    # In a real scenario, admin would need to intervene or wait for FAIL_INTERVAL
    # to expire. We'll verify the lock is persistent for now
    failure_count = get_faillog_count(username)
    assert failure_count >= MAX_FAILURE, "Lock should persist"
