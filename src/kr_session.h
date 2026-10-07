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
 * The session being opened or closed. In the keyring it is stored in the
 * compact form described at kr_sess_hdr_t.
 */
typedef struct {
	struct timespec creation;

	/* controlled by PAM module */
	uuid_t session_id;

	pid_t pid;			/* getpid() of PAM application */
	pid_t sid;			/* getsid() of PAM application */
	uint32_t flags;			/* internal flags about session */
	int origin_family;		/* AF_UNIX, AF_INET, AF_INET6 */

	kr_cred_t cred;			/* based on PAM_USER */
	kr_origin_t origin;
	kr_pam_item_t pam_item;		/* other pam_set_item() items */

	/* opaque info from PAM standpoint provided by PAM_TN_ENV_SES_DATA,
	 * truncated to fit */
	char json_data[2492];
} kr_sess_t;

/* Version of the session key payload. Version 1 was kr_sess_t itself. */
#define KR_SESS_VERSION 2

/**
 * @brief	fixed part of a session as stored in the keyring
 *
 * The payload of a session key is this header followed by the session's
 * strings, each NUL-terminated, in this order: username, service, ruser,
 * rhost, tty, security label (AF_UNIX origin only), json data. Unset strings
 * are empty. Storing kr_sess_t as is would cost every session its 4 KiB of
 * mostly empty arrays in uid 0's key quota.
 */
typedef struct {
	uint32_t version;		/* offset 0, size 4 - KR_SESS_VERSION */
	uint32_t flags;			/* offset 4, size 4 */
	struct timespec creation;	/* offset 8, size 16 */
	uuid_t session_id;		/* offset 24, size 16 */
	pid_t pid;			/* offset 40, size 4 */
	pid_t sid;			/* offset 44, size 4 */
	int origin_family;		/* offset 48, size 4 */
	uid_t uid;			/* offset 52, size 4 */
	gid_t gid;			/* offset 56, size 4 */
	union {
		struct {
			pid_t pid;
			uid_t uid;
			gid_t gid;
			uid_t loginuid;
		} unix_origin;		/* kr_origin_unix_t without its label */
		kr_origin_tcp_t tcp_origin;
	} origin;			/* offset 60, size 40 */
	uint32_t pad;			/* offset 100, size 4 */
} kr_sess_hdr_t;

_Static_assert(sizeof(kr_sess_hdr_t) == 104, "kr_sess_hdr_t unexpected size");

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
 * @brief find a session that this process opened on another PAM handle
 *
 * For pam_close_session() on a handle that did not open the session (Samba
 * does this). The session is matched by the calling process, PAM_SERVICE and
 * PAM_TTY; sessions without a tty are never matched.
 *
 * @param[in] pamh - PAM handle the session is being closed on
 * @param[in] session_keyring - SESSIONS keyring of PAM_USER
 * @param[out] sess_out - payload of the matching session
 *
 * @return key serial of the session, or -1 if none matches
 */
key_serial_t ptn_kr_find_session(pam_handle_t *pamh, key_serial_t session_keyring,
                                 kr_sess_t *sess_out);

/**
 * @brief copy the PAM items stored with a session from a PAM handle
 *
 * Items that are not set are left empty. Values are truncated as they are
 * when stored in the keyring.
 */
void ptn_kr_get_pam_items(pam_handle_t *pamh, kr_pam_item_t *items);

/**
 * @brief get count of active sessions for a user
 *
 * Unlinks keys that are revoked, expired or malformed, or whose process has
 * exited, then counts the sessions that remain.
 *
 * @param[in] session_keyring - SESSIONS keyring of PAM_USER
 * @param[out] count_out - Pointer to store the session count
 * @param[out] err - Error message structure
 *
 * @return PAM response (PAM_SUCCESS, PAM_SERVICE_ERR, etc)
 */
int ptn_kr_get_session_count(key_serial_t session_keyring, size_t *count_out,
                             kr_err_msg_t *err);

#endif /* _KR_SESSION_H_ */
