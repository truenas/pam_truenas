// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef _PAM_TRUENAS_JSON_H_
#define _PAM_TRUENAS_JSON_H_

#include <jansson.h>
#include "pam_truenas.h"
#include "error.h"

#define TRUENAS_KEY_REVOKED -1
#define TRUENAS_KEY_DOES_NOT_EXPIRE 0


/* JSON error types */
typedef enum json_error_type {
	JSON_E_SUCCESS = 0,
	JSON_E_PARSE,
	JSON_E_CRYPTO,
	JSON_E_NOT_FOUND
} json_resp_t;

/* Simple error handling for JSON operations */
typedef ptn_err_t json_error_info_t;

/* Authentication data parsing */
json_resp_t parse_json_auth_data(ptn_auth_data_t *auth_data,
				 pwenc_datum_t *json_data,
				 json_error_info_t *error_info);

/**
 * @brief parse pam_getenv() and pam_get_item() into session info
 *
 * pam_getenv() should have a PAM_TN_ENV_SES_DATA json string containing
 * session data. pam_get_item() provides PAM_USER, PAM_RHOST, PAM_RUSER,
 * and PAM_TTY.
 */
json_resp_t parse_json_sess_entry(pam_tn_ctx_t *ctx, json_error_info_t *err);
#endif /* _PAM_TRUENAS_JSON_H_ */
