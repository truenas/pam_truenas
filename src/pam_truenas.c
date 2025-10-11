// SPDX-License-Identifier: LGPL-3.0-or-later

#include "pam_truenas.h"
#include "json.h"
#include "keyring.h"
#include "tally.h"

static bool _pam_log_is_silent(uint32_t ctrl)
{
	return ctrl & PAM_TRUENAS_SILENT;
}

bool pam_log_is_debug_enabled(uint32_t ctrl)
{
	if (ctrl == -1) {
		return false;
	}

	if (_pam_log_is_silent(ctrl)) {
		return false;
	}

	if (!(ctrl & PAM_TRUENAS_DEBUG_ARG)) {
		return false;
	}

	return true;
}

static int _pam_populate_auth_data(pam_tn_ctx_t *ctx, const char *canonical_username)
{
	struct timespec now;
	keyring_err_msg_t error_msg;
	int result;

	/* Look up user keyring and load auth data */
	result = load_server_auth_data_from_keyring(ctx, &error_msg);
	if (result != 0) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "Failed to load auth data from keyring: %s",
			      error_msg.message);
		return PAM_AUTHINFO_UNAVAIL;
	}

	switch(ctx->json_auth_data.expiry) {
	case TRUENAS_KEY_REVOKED:
		return PAM_CRED_EXPIRED;
	case TRUENAS_KEY_DOES_NOT_EXPIRE:
		break;
	default:
		if (clock_gettime(CLOCK_REALTIME, &now)) {
			PAM_CTX_DEBUG(ctx, LOG_ERR,
				      "clock_gettime() failed: %s",
				      strerror(errno));
			return PAM_SERVICE_ERR;
		}
		if (now.tv_sec > ctx->json_auth_data.expiry) {
			PAM_CTX_DEBUG(ctx, LOG_ERR, "API key expired");
			return PAM_CRED_EXPIRED;
		}
	};
	return PAM_SUCCESS;
}

int ptn_process_tally(pam_tn_ctx_t *ctx)
{
	int retval = PAM_AUTH_ERR;
	bool is_locked;

	if (ctx->ctrl & PAM_TRUENAS_AUTH_SUCC) {
		retval = check_tally(ctx, &is_locked);
		if (retval != PAM_SUCCESS) {
			PAM_CTX_DEBUG(ctx, LOG_ERR, "Failed to check tally status");
			return retval;
		} else if (!is_locked) {
			reset_tally(ctx);

			// This module shouldn't impact overall status of auth
			// at this point
			retval = PAM_IGNORE;
		} else {
			PAM_CTX_DEBUG(ctx, LOG_ERR, "Credential is tally locked");
			retval = PAM_AUTH_ERR;
		}
	} else if (ctx->ctrl & PAM_TRUENAS_AUTH_FAIL) {
		// We hit this if authentication has failed and we need
		// to write a tally entry and return failure
		retval = write_tally(ctx);
		if (retval == PAM_SUCCESS) {
			retval = PAM_AUTH_ERR;
		}
	}

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] LEAVE: %s: %d\n",
		      ctx, "pam_sm_authenticate", retval);
	return retval;
}

/**
 * @brief pam_truenas implementation of pam_sm_authenticate() endpoint.
 *
 * This reads configuration from the `auth` PAM management group.
 *
 * Depending on configuration the pam_truenas module may perform multiple
 * roles:
 *
 * 1) It implements SCRAM authentication through PAM conversations
 * 2) It implements thread-safe equivalent of pam_faillock
 *
 * For SCRAM authentication a sample configurations are as follows:
 *
 * auth    [success=1 default=ignore] pam_truenas.so
 * # All authentication attempts are required to use SCRAM protocol
 *
 * auth    [success=1 default=ignore] pam_truenas.so allow_password_auth
 * # Authentication may be through either directly passing API key (password-style)
 * # or SCRAM protocol
 *
 * For failock implementation a sample configuration is as follows:
 * auth    [success=1 default=ignore] pam_truenas.so
 * # Basic authentication. On success jump down 1 (skipping `authfail` line)
 * auth    [default=done] pam_truenas.so authfail
 * # Authentication has failed and so we insert entry into the tally in the
 * # FAILLOCK keyring (see src/tally.c) and return last pam module value.
 * # whatever the last set value was
 * auth    required pam_truenas.so authsucc
 * # We've successfully authenticated and `authsucc` here means that the module
 * # should reset the tally stored in the FAILLOCK keyring (see src/tally.c).
 *
 * @note SCRAM protocol is described in RFC5802. This module swaps out the
 * original SHA1 algorithm for SHA512. This is more fully described in the
 * truenas_scram library located at https://github.com/truenas/truenas_scram.
 */
_PUBLIC_ PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
	const char *username = NULL;
	int retval = PAM_AUTH_ERR;
	pam_tn_ctx_t *ctx = NULL;
	bool created;

	retval = ptn_init_context(pamh, flags, argc, argv,
				  PAM_TRUENAS_AUTHENTICATE, &created, &ctx);
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] ENTER: %s\n",
		      pamh, "pam_sm_authenticate");

	retval = pam_get_user(ctx->pamh, &username, NULL);
	if ((retval != PAM_SUCCESS) || (!username)) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG,
			      "can not get the username: %s",
			      pam_strerror(ctx->pamh, retval));
		return PAM_SERVICE_ERR;
	}

	if (CHECK_TALLY(ctx->ctrl)) {
		// This is a tally-related operation that is checking or resetting
		// the faillog
		return ptn_process_tally(ctx);
	}

	retval = _pam_populate_auth_data(ctx, username);
	if (retval != PAM_SUCCESS) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] LEAVE: %s\n",
			      pamh, "pam_sm_authenticate");
		return retval;
	}

	/*
	 * Always try SCRAM authentication first.
	 * If ALLOW_PASSWORD_AUTH is set and we get PAM_AUTHTOK_ERR,
	 * it means the client sent a password instead of SCRAM message,
	 * so we fall back to password authentication.
	 */
	retval = ptn_do_scram_auth(ctx, username);
	if ((retval == PAM_AUTHTOK_ERR) && (ctx->ctrl & PAM_TRUENAS_ALLOW_PASSWORD_AUTH)) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG,
			      "SCRAM auth indicated password fallback, trying password auth");
		retval = ptn_do_plain_auth(ctx, username);
	}

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] LEAVE: %s for user (%s)\n",
		      pamh, "pam_sm_authenticate", username);

	return retval;
}

/* stub-out remaining PAM functions */
_PUBLIC_ PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags,
		   int argc, const char **argv)
{
	pam_tn_ctx_t *ctx = NULL;
	int retval;
	bool created;

	retval = ptn_init_context(pamh, flags, argc, argv,
				  PAM_TRUENAS_SETCRED, &created, &ctx);

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] ENTER: %s\n",
		      pamh, "pam_sm_setcred");

	if (retval != PAM_SUCCESS) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] LEAVE: %s\n",
			      pamh, "pam_sm_setcred");
		return PAM_IGNORE;
	}

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] LEAVE: %s\n",
		      pamh, "pam_sm_setcred");
	return retval;
}

_PUBLIC_ PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
	// not implemeented
	return PAM_IGNORE;
}

/**
 * @brief pam_truenas implementation of open_session() endpoint.
 *
 * This reads configuration from the `session` PAM management group.
 *
 * Sample line:
 * session required pam_truenas.so max_sessions=10
 *
 * The above causes the manual to reject access with PAM_PERM_DENIED
 * if the current session count is 10 or higher
 *
 * Sessions are inserted into the PAM_TRUENAS -> <username> -> SESSIONS
 * kernel keyring and are removed on pam_close_session()
 *
 * @note if the admin intends to accurately track all server sessions
 * then this should be placed within a common PAM configuration used
 * by all PAM services.
 */
_PUBLIC_ PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags,
			int argc, const char **argv)
{
	pam_tn_ctx_t *ctx = NULL;
	int retval;
	size_t session_count;
	bool created;
	kr_err_msg_t kr_err;

	retval = ptn_init_context(pamh, flags, argc, argv,
				  PAM_TRUENAS_OPEN_SESSION, &created, &ctx);

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] ENTER: %s\n",
		      pamh, "pam_sm_open_session");

	if (retval != PAM_SUCCESS) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] LEAVE: %s\n",
			      pamh, "pam_sm_open_session (no context)");
		return PAM_IGNORE;
	}

	/* Check if session limit is enabled and if limit would be exceeded */
	if (ctx->ctrl & PAM_TRUENAS_CHECK_SESSION_LIMIT) {
		retval = ptn_kr_get_session_count(ctx->kr.sessions_kr,
						  &session_count, &kr_err);
		if (retval != PAM_SUCCESS) {
			PAM_CTX_DEBUG(ctx, LOG_ERR,
				      "Failed to get session count: %s",
				      kr_err.message);
			return retval;
		}

		/* Check if opening a new session would exceed the limit */
		if (session_count >= ctx->max_sessions) {
			PAM_CTX_DEBUG(ctx, LOG_ERR,
				      "Session limit exceeded: %zu >= %u",
				      session_count, ctx->max_sessions);
			return PAM_PERM_DENIED;
		}
	}

	retval = ptn_open_session(ctx);
	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] LEAVE: %s\n",
		      pamh, "pam_sm_open_session");
	return retval;
}

/**
 * @brief pam_truenas implementation of close_session() endpoint.
 *
 * This reads configuration from the `session` PAM management group.
 *
 * Sample line:
 * session required pam_truenas.so max_sessions=10
 *
 * The above causes the manual to reject access with PAM_PERM_DENIED
 * if the current session count is 10 or higher
 *
 * Sessions are inserted into the PAM_TRUENAS -> <username> -> SESSIONS
 * kernel keyring and are removed on pam_close_session()
 *
 * @note if the admin intends to accurately track all server sessions
 * then this should be placed within a common PAM configuration used
 * by all PAM services.
 */
_PUBLIC_ PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags,
			 int argc, const char **argv)
{
	pam_tn_ctx_t *ctx = NULL;
	int retval;
	bool created;

	retval = ptn_init_context(pamh, flags, argc, argv,
				  PAM_TRUENAS_CLOSE_SESSION, &created, &ctx);

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] ENTER: %s\n",
		      pamh, "pam_sm_close_session");

	if (retval != PAM_SUCCESS) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] LEAVE: %s\n",
			      pamh, "pam_sm_close_session (no context)");
		return PAM_IGNORE;
	}

	retval = ptn_close_session(ctx);
	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "[pamh: %p] LEAVE: %s\n",
		      pamh, "pam_sm_close_session");

	return retval;
}

_PUBLIC_ PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
	// not implemeented
	return PAM_IGNORE;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _b_modstruct = {
	MODULE_NAME,
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};

#endif
