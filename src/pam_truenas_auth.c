// SPDX-License-Identifier: LGPL-3.0-or-later

#include "pam_truenas.h"
#include "json.h"
#include "keyring.h"

/**
 * PAM TrueNAS Authentication Implementation
 *
 * This module supports two authentication methods:
 * 1. SCRAM-SHA-512 challenge-response authentication (RFC 5802 with SHA-512)
 * 2. Direct password/API key verification (fallback mode)
 *
 * SCRAM Authentication Flow (ptn_do_scram_auth):
 * ================================================
 *   Step 1: Client → Server: ClientFirst message (username, client nonce)
 *           Function: _ptn_get_client_first()
 *
 *   Step 2: Server → Client: ServerFirst message (salt, iterations, server nonce)
 *           Function: _ptn_generate_server_first()
 *
 *   Step 3: Client → Server: ClientFinal message (client proof)
 *           Function: _ptn_get_client_final()
 *
 *   Step 4: Verify client proof against stored key
 *           Function: _ptn_verify_client_final()
 *
 *   Step 5: Server → Client: ServerFinal message (server proof) [optional]
 *           Function: _ptn_send_server_proof()
 *
 * Password/API Key Authentication Flow (ptn_do_plain_auth):
 * ===========================================================
 *   When allow_password_auth is enabled and client sends a password instead
 *   of a SCRAM message, the module falls back to direct verification:
 *   1. Extract password/API key from PAM_AUTHTOK
 *   2. Parse API key format if password_is_api_key flag is set (dbid-keymaterial)
 *   3. Compute SaltedPassword using PBKDF2-HMAC-SHA512
 *   4. Derive ServerKey from SaltedPassword
 *   5. Constant-time comparison of ServerKey with stored ServerKey
 *
 * All authentication data (salt, iterations, stored_key, server_key) is
 * retrieved from the kernel keyring and decrypted using the truenas_pwenc
 * library before authentication begins.
 */

/*
 * Obtain a password from PAM authtok. Based on pam_unix
 * @param[in] ctx ptdb_context
 * @param[in] user username provided to PAM
 * @param[out] pass password provided by PAM.
 *
 * @returns int Returns PAM_SUCCESS if successful else one of following:
 *     PAM_INCOMPLETE: failure to get via pam conversation
 */
static int _ptn_read_password(pam_tn_ctx_t *ctx,
			      const char *user,
			      const char **pass)
{
	int retval;
	const char *item;

	/*
	 * Try to get password from PAM_AUTHTOK. This could be set either:
	 * 1. By a previous module in the PAM stack
	 * 2. By our SCRAM auth attempt if the client sent a password instead
	 *    (the conversation response gets stored as PAM_AUTHTOK)
	 */
	retval = pam_get_authtok(ctx->pamh, PAM_AUTHTOK, &item , NULL);
	if (retval == PAM_SUCCESS) {
		*pass = item;
		item = NULL;

		PAM_CTX_DEBUG(ctx, LOG_DEBUG,
			      "pam_get_item returned a password");
	} else {
		if (retval != PAM_CONV_AGAIN) {
			PAM_TRUENAS_LOG(ctx->pamh, LOG_CRIT,
				    "auth could not identify password for [%s]",
				    user);
		} else {
			PAM_TRUENAS_LOG(ctx->pamh, LOG_DEBUG,
				    "conversation function is not ready yet");
			/*
			 * it is safe to resume this function so we translate this
			 * retval to the value that indicates we're happy to resume.
			 */
			retval = PAM_INCOMPLETE;
		}
	}

	return retval;
}

int ptn_do_plain_auth(pam_tn_ctx_t *pam_ctx, const char *username)
{
	const char *password = NULL;
	char *ppwd = NULL;
	bool match = false;
	scram_auth_data_t *server = &pam_ctx->json_auth_data.scram_data;
	scram_resp_t resp;
	scram_error_t error = {0};
	crypto_datum_t raw_pwd = {0};  // do NOT crypto_datum_free
	crypto_datum_t salted_pwd = {0};
	crypto_datum_t server_key = {0};

	if (_ptn_read_password(pam_ctx, username, &password) != PAM_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Could not retrieve user's password");
		return PAM_AUTHTOK_ERR;
	}

	if (password == NULL) {
		/*
		 * This is purely defensive programming. We shouldn't have case
		 * with pam_get_authtok() returns PAM_SUCCESS without an auth token
		 */
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR, "User password not set");
		return PAM_AUTHTOK_ERR;
	}

	/* password may be of form:
	 *
	 * 1-<keymaterial>
	 * or
	 * <keymaterial>
	 *
	 * We need to noramlize this so that password points
	 * to key material string
	 */
	if (pam_ctx->ctrl & PAM_TRUENAS_PASSWORD_IS_API_KEY) {
		// typically an API key consists of the numeric database id
		// and key material separated by a dash (-).
		// We'll try really hard here to guess at what's provided
		// If it's not our normal format, then we'll just assume
		// it's raw key material
		ppwd = strchr(password, '-');
		if (ppwd != NULL) {
			// This is our normal format. Advance the pointer
			// to the first character of the key material
			password = ++ppwd;
		}
	}

	if (*password == '\0') {
		// Don't try to process an empty string for password
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Password is empty string");
		return PAM_AUTH_ERR;
	}

	/*
	 * Recasting to unsigned char* is OK because the data will
	 * not be modified in generate_scram_auth_data
	 */
	raw_pwd = (crypto_datum_t) {
		.data = (unsigned char *)password,
		.size = strlen(password)
	};

	resp = scram_hi(&raw_pwd, &server->salt, server->iterations, &salted_pwd, &error);

	// We're done with password at this point since we've
	// generated required crypto datum
	// Note that we're *NOT* freeing password itself. This is because it's the
	// authtoken (not a copy) stored in the pam handle.
	pam_overwrite_object(&raw_pwd);
	password = NULL;

	if (resp != SCRAM_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to generate scram SaltedPassword: (%s)",
			      error.message);
		return PAM_AUTH_ERR;
	}

	/* Create server key for digest comparison */
	resp = scram_create_server_key(&salted_pwd, &server_key, &error);
	crypto_datum_clear(&salted_pwd, true);

	if (resp != SCRAM_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to generate scram ServerKey: (%s)",
			      error.message);
		return PAM_AUTH_ERR;
	}

	resp = scram_constant_time_compare(&server_key,
					   &server->server_key,
					   &match,
					   &error);

	crypto_datum_clear(&server_key, true);
	if (resp != SCRAM_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to compare ServerKey: (%s)",
			      error.message);
		return PAM_AUTH_ERR;
	}

	if (!match) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR, "digest did not match");
	}

	return match ? PAM_SUCCESS : PAM_AUTH_ERR;
}

#define CLIENT_FIRST "Send SCRAM ClientFirst message"
#define CLIENT_FIRST_PWD CLIENT_FIRST " or password"

static
int _ptn_get_client_first(pam_tn_ctx_t *pam_ctx,
			  const struct pam_conv *conv,
			  scram_client_first_t **cfirst)
{
	struct pam_message msg = (struct pam_message) {
		.msg_style = PAM_PROMPT_ECHO_OFF,
		.msg = "Send SCRAM ClientFirst message"
	};
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp = NULL;
	bool maybe_password = pam_ctx->ctrl & PAM_TRUENAS_ALLOW_PASSWORD_AUTH;
	int retval;
	scram_error_t error;
	scram_resp_t ret;

	msg.msg = maybe_password ? CLIENT_FIRST_PWD : CLIENT_FIRST;

	retval = conv->conv(1, &pmsg, &resp, conv->appdata_ptr);
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	if (resp[0].resp == NULL) {
		free(resp);
		return PAM_AUTH_ERR;
	}

	ret = scram_deserialize_client_first_message(resp[0].resp, cfirst, &error);
	if (ret != SCRAM_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to parse client first message: (%s)",
			      error.message);
		if (maybe_password && (ret == SCRAM_E_PARSE_ERROR)) {
			// Client sent a password instead of SCRAM message
			// Store it as PAM_AUTHTOK for password auth fallback
			retval = pam_set_item(pam_ctx->pamh, PAM_AUTHTOK, resp[0].resp);
			if (retval != PAM_SUCCESS) {
				PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
					      "Failed to store password in PAM_AUTHTOK");
				retval = PAM_AUTH_ERR;
			} else {
				// Signal to caller that password auth should be attempted
				retval = PAM_AUTHTOK_ERR;
			}
		} else {
			// just default to AUTH error
			retval = PAM_AUTH_ERR;
		}
	}

	// Securely clear response before freeing (may contain password)
	pam_overwrite_string(resp[0].resp);
	free(resp[0].resp);
	free(resp);
	return retval;
}

static
int _ptn_generate_server_first(pam_tn_ctx_t *pam_ctx,
			       scram_client_first_t *cfirst,
			       scram_server_first_t **sfirst)
{
	scram_resp_t ret;
	scram_error_t error;
	scram_auth_data_t auth = pam_ctx->json_auth_data.scram_data;

	ret = scram_create_server_first_message(cfirst,
						&auth.salt,
						auth.iterations,
						sfirst,
						&error);

	if (ret != SCRAM_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to generate server first message: (%s)",
			      error.message);
	}

	return ret == SCRAM_E_SUCCESS ? PAM_SUCCESS : PAM_AUTH_ERR;
}

static
int _ptn_get_client_final(pam_tn_ctx_t *pam_ctx,
			  const struct pam_conv *conv,
			  scram_server_first_t *sfirst,
			  scram_client_final_t **cfinal)
{
	struct pam_message msg;
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp = NULL;
	int retval;
	scram_error_t error;
	scram_resp_t ret;
	char *sfirst_str = NULL;

	// Send client RFC-serialized server-first-message
	ret = scram_serialize_server_first_message(sfirst, &sfirst_str, &error);
	if (ret != SCRAM_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to serialize server first message: (%s)",
			      error.message);
		return PAM_SYSTEM_ERR;
	}

	msg = (struct pam_message) {
		.msg_style = PAM_PROMPT_ECHO_OFF,
		.msg = sfirst_str
	};

	retval = conv->conv(1, &pmsg, &resp, conv->appdata_ptr);
	pam_overwrite_string(sfirst_str);
	free(sfirst_str);

	if (retval != PAM_SUCCESS) {
		return retval;
	}

	if (resp[0].resp == NULL) {
		free(resp);
		return PAM_AUTH_ERR;
	}

	ret = scram_deserialize_client_final_message(resp[0].resp, cfinal, &error);
	if (ret != SCRAM_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to parse client final message: (%s)",
			      error.message);
		// just default to AUTH error
		retval = PAM_AUTH_ERR;
	}

	/*
	 * The client final message string contains a client proof.
	 * This in itself is not overly sensitive, but it's good
	 * practice to be somewhat paranoid
	 */
	pam_overwrite_string(resp[0].resp);
	free(resp[0].resp);
	free(resp);
	return retval;
}

static
int _ptn_verify_client_final(pam_tn_ctx_t *pam_ctx,
			     scram_client_first_t *cfirst,
			     scram_server_first_t *sfirst,
			     scram_client_final_t *cfinal)
{
	scram_resp_t ret;
	scram_error_t error;
	crypto_datum_t *skey = &pam_ctx->json_auth_data.scram_data.stored_key;

	ret = scram_verify_client_final_message(cfirst,
						sfirst,
						cfinal,
						skey,
						&error);

	if (ret != SCRAM_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to verify client final message: (%s)",
			      error.message);
	}

	return ret == SCRAM_E_SUCCESS ? PAM_SUCCESS : PAM_AUTH_ERR;
}

/*
 * Following is void because failure to send server proof is non-fatal
 * from server perspective.
 */
static
void _ptn_send_server_proof(pam_tn_ctx_t *pam_ctx,
			    const struct pam_conv *conv,
			    scram_client_first_t *cfirst,
			    scram_server_first_t *sfirst,
			    scram_client_final_t *cfinal)
{
	struct pam_message msg;
	const struct pam_message *pmsg = &msg;
	struct pam_response *resp = NULL;
	int retval;
	scram_error_t error;
	scram_resp_t ret;
	char *sfinal_str = NULL;
	scram_server_final_t *sfinal = NULL;
	scram_auth_data_t auth = pam_ctx->json_auth_data.scram_data;

	ret = scram_create_server_final_message(cfirst, sfirst, cfinal,
						&auth.stored_key,
						&auth.server_key,
						&sfinal,
						&error);

	if (ret != SCRAM_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to create server final message: (%s)",
			      error.message);
		goto cleanup;
	}

	// Send client RFC-serialized server-first-message
	ret = scram_serialize_server_final_message(sfinal, &sfinal_str, &error);
	if (ret != SCRAM_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to serialize server final message: (%s)",
			      error.message);
		goto cleanup;
	}

	// Send server proof as PAM_TEXT_INFO since we don't expect response
	msg = (struct pam_message) {.msg_style = PAM_TEXT_INFO,.msg = sfinal_str};
	retval = conv->conv(1, &pmsg, &resp, conv->appdata_ptr);
	if (retval != PAM_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to send server final message: (%d)",
			      retval);
	}

cleanup:
	clear_scram_server_final_message(sfinal);
	free(sfinal);
	pam_overwrite_string(sfinal_str);
	free(sfinal_str);
	free(resp);
}

int ptn_do_scram_auth(pam_tn_ctx_t *pam_ctx, const char *username)
{
	const struct pam_conv *conv;
	int retval;
	scram_client_first_t *cfirst = NULL;
	scram_server_first_t *sfirst = NULL;
	scram_client_final_t *cfinal = NULL;

	retval = pam_get_item(pam_ctx->pamh, PAM_CONV, (const void **)&conv);
	if (retval != PAM_SUCCESS) {
		return retval;
	}

	// get client-first-message
	retval = _ptn_get_client_first(pam_ctx, conv, &cfirst);
	if (retval != PAM_SUCCESS) {
		goto cleanup;
	}

	// generate server-first-message to request client-final-message
	retval = _ptn_generate_server_first(pam_ctx, cfirst, &sfirst);
	if (retval != PAM_SUCCESS) {
		goto cleanup;
	}

	// get client-final-message
	retval = _ptn_get_client_final(pam_ctx, conv, sfirst, &cfinal);
	if (retval != PAM_SUCCESS) {
		goto cleanup;
	}

	// validate client proof
	retval = _ptn_verify_client_final(pam_ctx, cfirst, sfirst, cfinal);
	if (retval != PAM_SUCCESS) {
		goto cleanup;
	}

	// sending a final proof is non-fatal
	_ptn_send_server_proof(pam_ctx, conv, cfirst, sfirst, cfinal);

cleanup:
	clear_scram_client_first_message(cfirst);
	clear_scram_client_final_message(cfinal);
	clear_scram_server_first_message(sfirst);
	free(cfirst);
	free(cfinal);
	free(sfirst);
	return retval;
}
