// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef _INCLUDES_H_
#define _INCLUDES_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <syslog.h>
#include <unistd.h>
#include <semaphore.h>
#include <uuid/uuid.h>
#include <keyutils.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <truenas_scram.h>
#include <truenas_pwenc.h>
#include "error.h"
#include "cleanup.h"

/* Constants */
#define MODULE_NAME "pam_truenas"
#define MODULE_DATA_NAME "pam_truenas_data"
#define PAM_TN_VAL_UNKNOWN "<unknown>"

/* Keyring names */
#define PAM_KEYRING_NAME "PAM_TRUENAS"
#define PAM_SESSION_NAME "SESSIONS"
#define PAM_API_KEY_NAME "API_KEYS"
#define PAM_FAILLOG_NAME "FAILLOG"

/* context flags */
#define PAM_TRUENAS_SILENT	0x00000001	/* Don't emit any messages */
#define PAM_TRUENAS_DEBUG_ARG	0x00000002	/* Enable debug logging */
#define PAM_TRUENAS_DEBUG_STATE	0x00000004	/* Log internal state for debugging */
#define PAM_TRUENAS_AUTH_SUCC	0x00000008	/* Check/reset tally on auth success */
#define PAM_TRUENAS_AUTH_FAIL	0x00000010	/* Increment tally on auth failure */
#define PAM_TRUENAS_ALLOW_PASSWORD_AUTH	0x00000020	/* Allow fallback to password auth if not SCRAM */
#define PAM_TRUENAS_PASSWORD_IS_API_KEY	0x00000040	/* Password contains API key material */
#define PAM_TRUENAS_USE_ENV_CONFIG	0x00000080	/* Check PAM environment variables for configuration */
#define PAM_TRUENAS_CHECK_SESSION_LIMIT	0x00000100	/* Check if user has exceeded max_sessions limit */


#define CHECK_TALLY(ctrl) \
	(ctrl & (PAM_TRUENAS_AUTH_SUCC | PAM_TRUENAS_AUTH_FAIL))

/* Session environment variable name */
#define PAM_TN_ENV_ENABLED '1'
#define PAM_TN_ENV_PASSWD "pam_truenas_password_auth"
#define PAM_TN_ENV_API_KEY "pam_truenas_password_auth_is_api_key"
#define PAM_TN_ENV_SES_UUID "pam_truenas_session_uuid"
#define PAM_TN_ENV_SES_DATA "pam_truenas_session_data"

/* Security label max size */
#ifndef SECURITY_LABEL_MAX
#define SECURITY_LABEL_MAX 256
#endif

/* Login name max size */
#ifndef LOGIN_NAME_MAX
#define LOGIN_NAME_MAX 256
#endif

/* Special expiry values */
#define TRUENAS_KEY_DOES_NOT_EXPIRE 0
#define TRUENAS_KEY_REVOKED -1

#define _PUBLIC_ __attribute__ ((visibility("default")))

/* Generic macros */
#define STATIC_ASSERT_CHAR_PTR(expr) \
	_Static_assert( \
		__builtin_types_compatible_p(typeof(expr), char *) || \
		__builtin_types_compatible_p(typeof(expr), const char *), \
		"Expression must be char* or const char*" \
	)

#define PTN_STR_OR_UNKNOWN(x)\
	({ STATIC_ASSERT_CHAR_PTR(x); \
	 ((x) ? (x) : PAM_TN_VAL_UNKNOWN); \
	 })

/* PAM debug macros */
#define PAM_TRUENAS_LOG(pamh, priority, fmt, ...) \
	pam_syslog(pamh, priority, fmt " [%s]", ##__VA_ARGS__, __location__)

#define PAM_TRUENAS_DEBUG(pamh, ctrl, priority, fmt, ...) \
do { \
	if (pam_log_is_debug_enabled(ctrl)) { \
		PAM_TRUENAS_LOG(pamh, priority, fmt, ##__VA_ARGS__); \
	} \
} while(0)

#define PAM_CTX_DEBUG(ctx, priority, fmt, ...) \
	PAM_TRUENAS_DEBUG(ctx->pamh, ctx->ctrl, priority, fmt, ##__VA_ARGS__)

/* Utils functions */
char *canonicalize_username(const char *uname_in, uid_t *uid_out, gid_t *gid_out);
bool ptn_parse_uint(const char *str_in, unsigned int *val_out, unsigned int max_val);

#endif /* _INCLUDES_H_ */
