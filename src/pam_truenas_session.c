// SPDX-License-Identifier: LGPL-3.0-or-later

#include "pam_truenas.h"
#include "json.h"
#include "kr_session.h"
#include "error.h"

int ptn_open_session(pam_tn_ctx_t *pam_ctx)
{
	json_error_info_t json_err;
	kr_err_msg_t kr_err;
	json_resp_t resp;
	int retval;

	/* Parse JSON session data and populate session_info */
	resp = parse_json_sess_entry(pam_ctx, &json_err);
	if (resp != JSON_E_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to parse session data: %s",
			      json_err.message);
		return PAM_SESSION_ERR;
	}

	/* Store session in keyring and save key ID */
	retval = ptn_kr_open_session(pam_ctx->pamh, pam_ctx->ctrl,
				      pam_ctx->kr.sessions_kr,
				      &pam_ctx->session_info,
				      &pam_ctx->session_key_id, &kr_err);
	if (retval != PAM_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to store session in keyring: %s",
			      kr_err.message);
		return retval;
	}

	return PAM_SUCCESS;
}

int ptn_close_session(pam_tn_ctx_t *pam_ctx)
{
	kr_err_msg_t kr_err;
	int retval;

	/* Remove session from keyring using saved key ID */
	retval = ptn_kr_close_session(pam_ctx->pamh, pam_ctx->ctrl,
				       &pam_ctx->session_info,
				       pam_ctx->session_key_id, &kr_err);
	if (retval != PAM_SUCCESS) {
		PAM_CTX_DEBUG(pam_ctx, LOG_ERR,
			      "Failed to remove session from keyring: %s",
			      kr_err.message);
		return retval;
	}

	/* Clear the key ID */
	pam_ctx->session_key_id = 0;

	return PAM_SUCCESS;
}
