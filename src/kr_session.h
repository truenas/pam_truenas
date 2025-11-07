// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef _KR_SESSION_H_
#define _KR_SESSION_H_

#include "includes.h"
#include "error.h"

/* Error message type for keyring operations */
typedef ptn_err_t kr_err_msg_t;

/**
 * @brief	credential based on PAM_USER
 *
 * NSS lookup results for the username specified as PAM_USER
 * This *does not* reflect the euid/egid of the process at the
 * time the session was opened because sessions are usually opened
 * while the process has euid 0
 */
typedef struct {
	char name[LOGIN_NAME_MAX];
	uid_t uid;
	gid_t gid;
} kr_cred_t;

typedef struct {
	pid_t pid;
	uid_t uid;
	gid_t gid;
	uid_t loginuid;
	char sec[SECURITY_LABEL_MAX];
} kr_origin_unix_t;

typedef struct {
	struct in6_addr loc_addr;
	struct in6_addr rem_addr;
	uint16_t loc_port;
	uint16_t rem_port;
	bool ssl;
} kr_origin_tcp_t;

/**
 * @brief	union containing basic information about connection origin
 *
 * This provides basic information about the connection origin of the
 * session that is being opened by the pam_open_session() call. It is
 * provided by JSON string set in PAM_TN_ENV_SES_DATA.
 */
typedef union {
	kr_origin_unix_t unix_origin;
	kr_origin_tcp_t tcp_origin;
} kr_origin_t;

/**
 * @brief	pam item values at time of session open
 *
 * This struct contains PAM items at the time the session was opened.
 *
 * @note	PAM applications can change these values via pam_set_item(3)
 * 		at any point.
 */
typedef struct {
	char service[NAME_MAX];
	char ruser[NAME_MAX];
	char rhost[NAME_MAX];
	char tty[NAME_MAX];
} kr_pam_item_t;

/**
 * @brief	session information for pam session
 *
 * This struct is stored in LMDB for session tracking.
 */
typedef struct {
	struct timespec creation;	/* offset 0, size 16 */

	/* controlled by PAM module */
	uuid_t session_id;		/* offset 16, size 16 - lmdb key */

	pid_t pid;			/* offset 32, size 4 - getpid() of PAM application */
	pid_t sid;			/* offset 36, size 4 - getsid() of PAM application */
	uint32_t flags;			/* offset 40, size 4 - internal flags about session */
	int origin_family;		/* offset 44, size 4 - AF_UNIX, AF_INET, AF_INET6 */

	kr_cred_t cred;		/* offset 48, size 264 - based on PAM_USER */
	kr_origin_t origin;		/* offset 312, size 272 */
	kr_pam_item_t pam_item;	/* offset 584, size 1020 - other pam_set_item() items */

	/* opaque info from PAM standpoint provided by PAM_TN_ENV_SES_DATA
	 */
	char json_data[2492];
} kr_sess_t;

_Static_assert(sizeof(kr_sess_t) == 4096, "kr_sess_t unexpected size");

/**
 * @brief create an entry in kernel keyring for the session
 *
 * This function stores the session in the kernel keyring. It assumes
 * that kr_sess_t has been fully populated by json.c
 *
 * @param[in] pamh - initialized pam handle
 * @param[in] ctrl - pam configuration flags for specific operation
 * @param[in] sess - filled out keyring session info
 * @param[out] key_out - keyring ID of new keyring-based session
 * @param[out] err - error information on failure
 *
 * @return PAM response (PAM_SUCCESS, PAM_SERVICE_ERR, etc)
 */
int ptn_kr_open_session(pam_handle_t *pamh, uint32_t ctrl, key_serial_t user_kr,
                        kr_sess_t *sess, key_serial_t *key_out, kr_err_msg_t *err);

/**
 * @brief delete entry from kernel keyring for the session
 *
 * This function removes the session from the keyring using the key_id from open_session.
 * Uses the key ID passed in (from open_session)
 *
 * @param[in] pamh - initialized pam handle
 * @param[in] ctrl - pam configuration flags for specific operation
 * @param[in] sess - filled out keyring session info
 * @param[out] key_out - keyring ID of new keyring-based session
 * @param[out] err - error information on failure
 *
 * @return PAM response (PAM_SUCCESS, PAM_SERVICE_ERR, etc)
 */
int ptn_kr_close_session(pam_handle_t *pamh, uint32_t ctrl, kr_sess_t *sess,
                         key_serial_t key_id, kr_err_msg_t *err);

/**
 * @brief get count of active sessions for a user
 *
 * This function counts the number of valid (non-expired/non-revoked) session
 * keys in the user's session keyring.
 *
 * @param[in] user_kr  - User keyring serial containing the SESSIONS keyring
 * @param[in] count_out - Pointer to store the session count
 * @param[out] err - Error message structure
 *
 * @return PAM response (PAM_SUCCESS, PAM_SERVICE_ERR, etc)
 */
int ptn_kr_get_session_count(key_serial_t user_kr, size_t *count_out,
                              kr_err_msg_t *err);

#endif /* _KR_SESSION_H_ */
