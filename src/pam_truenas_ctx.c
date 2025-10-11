// SPDX-License-Identifier: LGPL-3.0-or-later

#include "pam_truenas.h"
#include "json.h"
#include "keyring.h"

#define USER_SESSIONS_MAX_VAL 1024

static
void parse_max_session(const pam_handle_t *pamh,
		       uint32_t flags,
		       const char *parm,
		       uint32_t *plimit)
{
	char *sep;
	int ret;

	if (plimit == NULL) {
		/* Caller doesn't care about session limit */
		return;
	}

	sep = strchr(parm, '=');
	if (sep == NULL) {
		PAM_TRUENAS_DEBUG(pamh, flags, LOG_ERR,
				  "\"max_sessions\" param missing expected "
				  "delimiter");
		return;
	}

	ret = ptn_parse_uint(sep++, plimit, USER_SESSIONS_MAX_VAL);
	if (ret != PAM_SUCCESS) {
		PAM_TRUENAS_DEBUG(pamh, flags, LOG_ERR,
				  "%s: failed to parse max_sessions",
				  parm);
	}
}

/**
 * Parse username format "mary:1" or "mary" and load auth data from keyring
 * If no separator, DBID defaults to 0 (regular user auth)
 *
 * @param[in] ctx PAM context
 * @param[in] username_with_dbid Username in format "username:dbid" or "username"
 * @param[out] real_username_out Parsed username (caller must free)
 *
 * @returns int Returns PAM_SUCCESS on success, appropriate PAM error on failure
 */
static int _pam_parse_username_and_load_keyring(pam_tn_ctx_t *ctx,
						const char *username_with_dbid,
						char **real_username_out)
{
	char username_buf[NAME_MAX + 1];
	char *colon_pos;
	char *dbid_str;
	unsigned int api_key_dbid = 0; /* Default to 0 for regular user auth */
	keyring_err_msg_t error_msg;
	key_serial_t user_kr;
	char *canonical_username = NULL;

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "parsing username: %s",
			PTN_STR_OR_UNKNOWN(username_with_dbid));

	/* Copy username to working buffer */
	strlcpy(username_buf, username_with_dbid, sizeof(username_buf));

	colon_pos = strchr(username_buf, ':');
	if (colon_pos) {
		/* Split username and dbid */
		*colon_pos = '\0';
		dbid_str = colon_pos + 1;

		/* Parse API key dbid */
		if (!ptn_parse_uint(dbid_str, &api_key_dbid, 0)) {
			PAM_CTX_DEBUG(ctx, LOG_ERR,
				      "Invalid API key dbid: %s (error: %s)",
				      dbid_str, strerror(errno));
			return PAM_USER_UNKNOWN;
		}
	}

	/* Get passwd struct for username using getpwnam_r to get canonical name */
	canonical_username = canonicalize_username(username_buf, NULL, NULL);
	if (canonical_username == NULL) {
		PAM_CTX_DEBUG(ctx, LOG_WARNING,
			      "%s: failed to look up user account: %s",
			      username_buf,
			      errno == ENOENT ? "user does not exist" : strerror(errno));
		return PAM_AUTHINFO_UNAVAIL;
	}

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "%s: username canonicalized to %s with dbid: %u",
			PTN_STR_OR_UNKNOWN(username_with_dbid), canonical_username, api_key_dbid);

	/* Get or create user keyring using canonical username */
	user_kr = keyring_get_truenas_user_keyring(ctx->kr.module_kr, canonical_username);
	if (user_kr == -1) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "Failed to get user keyring for %s: %s",
			      canonical_username, strerror(errno));
		free(canonical_username);
		return PAM_AUTHINFO_UNAVAIL;
	}

	/* Store the user keyring in the context */
	ctx->kr.user_kr = user_kr;

	ctx->json_auth_data.principal.api_key_id = api_key_dbid;
	strlcpy(ctx->json_auth_data.principal.username, canonical_username,
		SCRAM_MAX_USERNAME_LEN);

	*real_username_out = canonical_username;
	return PAM_SUCCESS;
}

static
int _ptn_set_user(pam_tn_ctx_t *ctx,
		  const char *canonical_uname,
		  const char **uname_out)
{
	int retval;
	const char *uname = NULL;

	/*
	 * We may have sliced username / api key based on ":"
	 * Change what's stored so that other modules calling getpwnam on
	 * correct name and not concatenated username + api key id
	 */
	retval = pam_set_item(ctx->pamh, PAM_USER, (const void*)canonical_uname);
	if (retval != PAM_SUCCESS) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG,
			      "%s: failed to set PAM_USER: %s",
			      canonical_uname, pam_strerror(ctx->pamh, retval));
		return PAM_SERVICE_ERR;
	}

	/*
	 * Check that we now have the expected value for PAM_USER before
	 * freeing canoncial_uname
	 */
	retval = pam_get_user(ctx->pamh, &uname, NULL);
	if ((retval != PAM_SUCCESS) || (!uname)) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG,
			      "can not get the username: %s",
			      pam_strerror(ctx->pamh, retval));
		return PAM_SERVICE_ERR;
	}

	if (strcmp(uname, canonical_uname) != 0) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG,
			      "%s: unexpected PAM_USER. Expected: %s",
			      uname, canonical_uname);
		return PAM_SERVICE_ERR;
	}

	*uname_out = uname;
	return PAM_SUCCESS;
}

static
int _ptn_fill_keyring(pam_tn_ctx_t *ctx)
{
	char *canonical_uname = NULL;
	const char *uname = NULL;  // from pam handle
	int retval;
	key_serial_t ukr;

	/*
	 * Retreive the username from the pam handle or
	 * initiate a PAM conversation to get the username
	 */
	retval = pam_get_user(ctx->pamh, &uname, NULL);
	if ((retval != PAM_SUCCESS) || (!uname)) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG,
			      "can not get the username: %s",
			      pam_strerror(ctx->pamh, retval));
		return PAM_SERVICE_ERR;
	}

	/* Parse username and load user keyring */
	retval = _pam_parse_username_and_load_keyring(ctx, uname, &canonical_uname);
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	/* Ensure PAM_USER is set to our canonical_uname */
	retval = _ptn_set_user(ctx, canonical_uname, &uname);
	free(canonical_uname);
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	PAM_CTX_DEBUG(ctx, LOG_DEBUG, "Set PAM_USER to: %s", uname);
	ukr = ctx->kr.user_kr;

	/* Now fill remaining keyring items */
	if (((ctx->kr.api_keys_kr = keyring_get_api_key_keyring(ukr)) == -1) ||
	    ((ctx->kr.sessions_kr = keyring_get_session_keyring(ukr)) == -1)) {
		PAM_CTX_DEBUG(ctx, LOG_DEBUG,
			      "%s: failed to populate keyrings: %s",
			      uname, strerror(errno));
		return PAM_SERVICE_ERR;
	}

	return PAM_SUCCESS;
}

uint32_t ptn_pam_parse(const pam_handle_t *pamh,
		       int flags,
		       int argc,
		       const char **argv,
		       uint32_t *psession_limit)
{
	uint32_t ctrl = 0;
	int i;
	const char **v;

	if (flags & PAM_SILENT) {
		ctrl |= PAM_TRUENAS_SILENT;
	}

	/* step through arguments */
	for (i=argc,v=argv; i-- > 0; ++v) {

		/* generic options */
		if (!strcmp(*v,"debug"))
			ctrl |= PAM_TRUENAS_DEBUG_ARG;
		else if (!strcasecmp(*v, "debug_state"))
			ctrl |= PAM_TRUENAS_DEBUG_STATE;
		else if (!strcasecmp(*v, "silent"))
			ctrl |= PAM_TRUENAS_SILENT;
		else if (!strcasecmp(*v, "allow_password_auth"))
			ctrl |= PAM_TRUENAS_ALLOW_PASSWORD_AUTH;
		else if (!strcasecmp(*v, "password_is_api_key"))
			ctrl |= PAM_TRUENAS_PASSWORD_IS_API_KEY;
		else if (!strcasecmp(*v, "use_env_config"))
			ctrl |= PAM_TRUENAS_USE_ENV_CONFIG;
		else if (!strcasecmp(*v, "authfail"))
			ctrl |= PAM_TRUENAS_AUTH_FAIL;
		else if (!strcasecmp(*v, "authsucc"))
			ctrl |= PAM_TRUENAS_AUTH_SUCC;
		else if (!strcasecmp(*v, "max_sessions")) {
			parse_max_session(pamh, ctrl, *v, psession_limit);
			ctrl |= PAM_TRUENAS_CHECK_SESSION_LIMIT;
		}
	}

	return ctrl;
};

/**
 * cleanup function for pam_tn_ctx_t
 */
void ptn_cleanup_context(pam_tn_ctx_t *ctx)
{
	if (!ctx) {
		return;
	}

	/* Clean up JSON authentication data */
	clear_scram_auth_data(&ctx->json_auth_data.scram_data);

	/* Clean up our session info */
	pam_overwrite_object(&ctx->session_info);

	/* Don't call pam_set_data here - it causes infinite recursion
	 * when called from the PAM cleanup callback (_ptn_cleanup_cb).
	 * PAM handles removing the data reference when calling the cleanup callback.
	 */
	free(ctx);
}

static void _ptn_cleanup_cb(pam_handle_t *pamh,
			    void *data,
			    int error_status)
{
	if (data == NULL) {
		return;
	}

	ptn_cleanup_context((pam_tn_ctx_t *)data);
}

int ptn_init_context(pam_handle_t *pamh,
		     int flags,
		     int argc,
		     const char **argv,
		     enum ptn_request_tp type,
		     bool *pcreated,
		     pam_tn_ctx_t **ctx_out)
{
	pam_tn_ctx_t *r = NULL;
	int ret;
	bool created = false;

	/* first check if handle already has cached data */
	ret = pam_get_data(pamh, MODULE_DATA_NAME, (const void **)&r);
	if (ret != PAM_SUCCESS) {
		r = calloc(1, sizeof(pam_tn_ctx_t));
		if (!r) {
			return PAM_BUF_ERR;
		}
		created = true;
		r->pamh = pamh;

		/*
		 * Try to find the keyring by name. If it doesn't exist,
		 * we'll signal that auth info is unavailable
		 */
		r->kr.module_kr = keyring_get_pam_keyring();
		if (r->kr.module_kr ==  -1) {
			PAM_TRUENAS_DEBUG(pamh, r->ctrl, LOG_ERR,
				      "Failed to find keyring '%s': %s\n",
				      PAM_KEYRING_NAME, strerror(errno));

			free(r);
			return PAM_AUTHINFO_UNAVAIL;
		}
	}

	r->ctrl = ptn_pam_parse(pamh, flags, argc, argv, &r->max_sessions);

	/*
	 * Check environment variables for additional configuration if enabled
	 *
	 * This is an option for dev / testing if developer wants to manage
	 * service module configuration through the pam environment. It
	 * requires explicit PAM configuration line to enable the developer
	 * feature.
	 */
	if (r->ctrl & PAM_TRUENAS_USE_ENV_CONFIG) {
		const char *env = pam_getenv(pamh, PAM_TN_ENV_PASSWD);
		if ((env != NULL) && (*env == PAM_TN_ENV_ENABLED)) {
			r->ctrl |= PAM_TRUENAS_ALLOW_PASSWORD_AUTH;
		}

		env = pam_getenv(pamh, PAM_TN_ENV_API_KEY);
		if ((env != NULL) && (*env == PAM_TN_ENV_ENABLED)) {
			r->ctrl |= PAM_TRUENAS_PASSWORD_IS_API_KEY;
		}
	}

	if (created) {
		/*
		 * set minimum 2 second delay on failure
		 * This is a fairly common default that can be adjusted upwards if required
		 * by PAM settings.
		 */
		pam_fail_delay(pamh, 2000000);

		/*
		 * Since this is the first time through the PAM truenas module we need
		 * to look up the user keyring, canonicalize the name, etc
		 */
		ret = _ptn_fill_keyring(r);
		if (ret != PAM_SUCCESS) {
			free(r);
			return ret;
		}

		ret = pam_set_data(pamh, MODULE_DATA_NAME, (const void **)r, _ptn_cleanup_cb);
		if (ret != PAM_SUCCESS) {
			/*
			 * Failure to set as module data means we have no cleanup
			 * function and will leak memory. Treat this as fatal and
			 * pre-emptively free
			 */
			PAM_CTX_DEBUG(r, LOG_ERR,
				      "%d: failed to set pam module data.",
				      ret);
			free(r);
			return ret;
		}
	}

	*ctx_out = r;
	*pcreated = created;
	return ret;
}
