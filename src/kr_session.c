// SPDX-License-Identifier: LGPL-3.0-or-later

#include "kr_session.h"
#include "keyring.h"
#include "pam_truenas.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <uuid/uuid.h>

/**
 * @brief Create an entry in kernel keyring for the session
 *
 * This function stores the session information in the kernel keyring after it has been
 * populated by parse_json_sess_entry.
 */
int
ptn_kr_open_session(pam_handle_t *pamh, uint32_t ctrl, key_serial_t session_keyring,
                    kr_sess_t *sess, key_serial_t *key_out, kr_err_msg_t *err)
{
	key_serial_t key_id;
	char key_desc[UUID_STR_LEN + 32] = { 0 };  /* UUID + ":" + pid (max 10 digits) + null */
	char env_str[64] = { 0 };  /* PAM_TN_ENV_SES_UUID=<uuid> */
	char *uuid_pos;
	size_t prefix_len = strlen(PAM_TN_ENV_SES_UUID);
	size_t uuid_len;
	int rc;

	/* key_out is required to return the key serial */
	if (!key_out) {
		ptn_set_error(err, "key_out parameter is required");
		return PAM_SESSION_ERR;
	}

	/* Convert UUID to string and append pid in format "UUID:pid" */
	uuid_unparse(sess->session_id, key_desc);
	uuid_len = strlen(key_desc);
	snprintf(key_desc + uuid_len, sizeof(key_desc) - uuid_len, ":%d", sess->pid);

	/* Add the session data to the keyring using "UUID:pid" as description */
	key_id = add_key("user", key_desc, sess, sizeof(kr_sess_t), session_keyring);
	if (key_id == -1) {
		ptn_set_error(err, "Failed to add session to keyring: %s", strerror(errno));
		return PAM_SESSION_ERR;
	}

	/* Return the key ID for later use */
	*key_out = key_id;

	/* Build PAM environment string with UUID (without pid) */
	memcpy(env_str, PAM_TN_ENV_SES_UUID, prefix_len);
	env_str[prefix_len] = '=';
	uuid_pos = env_str + prefix_len + 1;
	memcpy(uuid_pos, key_desc, uuid_len);  /* Copy just the UUID part */

	/* Set UUID string in PAM environment - pam_putenv makes its own copy */
	rc = pam_putenv(pamh, env_str);
	if (rc != PAM_SUCCESS) {
		PAM_TRUENAS_DEBUG(pamh, ctrl, LOG_WARNING,
				  "Failed to set session UUID in PAM environment: %s",
				  pam_strerror(pamh, rc));
	}

	PAM_TRUENAS_DEBUG(pamh, ctrl, LOG_DEBUG, "Session %s stored in keyring (key_id=%d)",
			  key_desc, key_id);

	return PAM_SUCCESS;
}

/**
 * @brief Delete entry from kernel keyring for the session
 *
 * This function removes the session entry using the key_serial_t from open_session.
 */
int
ptn_kr_close_session(pam_handle_t *pamh, uint32_t ctrl, kr_sess_t *sess,
                     key_serial_t key_id, kr_err_msg_t *err)
{
	char uuid_str[UUID_STR_LEN];

	/* If no key_id provided, we can't proceed */
	if (key_id == 0 || key_id == -1) {
		/* This might happen if open_session failed or wasn't called */
		PAM_TRUENAS_DEBUG(pamh, ctrl, LOG_DEBUG,
				  "No key_id for session close");
		return PAM_SUCCESS;
	}

	/* Convert UUID to string for logging */
	uuid_unparse(sess->session_id, uuid_str);

	/* Revoke the key - makes it immediately inaccessible */
	if (keyctl_revoke(key_id) == -1) {
		if (errno == ENOKEY) {
			/* Key doesn't exist - already removed */
			PAM_TRUENAS_DEBUG(pamh, ctrl, LOG_DEBUG,
					  "Session %s key already removed", uuid_str);
			return PAM_SUCCESS;
		}
		ptn_set_error(err, "Failed to revoke session key: %s", strerror(errno));
		return PAM_SESSION_ERR;
	}

	PAM_TRUENAS_DEBUG(pamh, ctrl, LOG_DEBUG, "Session %s revoked from keyring", uuid_str);

	return PAM_SUCCESS;
}

/**
 * @brief Extract PID from session key description
 *
 * Key descriptions have format "type;uid;gid;perm;UUID:pid"
 * This function extracts the pid portion.
 *
 * @param key_id The key serial to get description from
 * @param pid_out Pointer to store the extracted PID
 * @return 0 on success, -1 on error (including expired/revoked keys)
 */
static int
session_key_to_pid(key_serial_t key_id, pid_t *pid_out)
{
	char *desc_buf = NULL;
	char *description;
	char *pid_str;
	unsigned int pid_uint;
	int ret = -1;

	if (pid_out == NULL) {
		return -1;
	}

	/* Get key description in format "type;uid;gid;perm;description"
	 * This will fail for expired/revoked keys */
	if (keyctl_describe_alloc(key_id, &desc_buf) <= 0) {
		return -1;
	}

	/* Get last semicolon - description follows it */
	description = strrchr(desc_buf, ';');
	if (description == NULL) {
		errno = EINVAL;
		free (desc_buf);
		return -1;
	}

	description++;  /* Move past the semicolon */
	if (*description == '\0') {
		errno = EINVAL;
		free(desc_buf);
		return -1;
	}

	/* Find the colon separator in "UUID:pid" */
	pid_str = strchr(description, ':');
	if (pid_str == NULL) {
		errno = EINVAL;
		free(desc_buf);
		return -1;
	}

	pid_str++;  /* Move past the colon */
	if (*pid_str == '\0') {
		errno = EINVAL;
		free(desc_buf);
		return -1;
	}

	/* Parse PID using our utility function */
	if (!ptn_parse_uint(pid_str, &pid_uint, 0)) {
		errno = EINVAL;
		free(desc_buf);
		return -1;
	}

	*pid_out = (pid_t)pid_uint;
	ret = 0;

	free(desc_buf);
	return ret;
}

/**
 * @brief Get count of active sessions for a user
 *
 * This function counts the number of valid sessions by:
 * 1. Reading all keys in the session keyring
 * 2. Parsing key descriptions in format "UUID:pid"
 * 3. Checking if the pid is still alive using kill(pid, 0)
 * 4. Unlinking keys that are REVOKED, EXPIRED, or have dead PIDs
 */
int
ptn_kr_get_session_count(key_serial_t session_keyring, size_t *count_out, kr_err_msg_t *err)
{
	key_serial_t *krbuf = NULL;
	long bufsz;
	size_t i, cnt = 0;

	if (count_out == NULL) {
		ptn_set_error(err, "count_out parameter is required");
		return PAM_SYSTEM_ERR;
	}

	if (session_keyring <= 0) {
		ptn_set_error(err, "Invalid user session keyring");
		return PAM_SYSTEM_ERR;
	}

	/* Read and allocate an array of key_serial_t serials for keys in the session keyring */
	bufsz = keyctl_read_alloc(session_keyring, (void **)&krbuf);
	if (bufsz == -1) {
		ptn_set_error(err, "Failed to read session keyring: %s", strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	if ((bufsz % sizeof(key_serial_t)) != 0) {
		ptn_set_error(err, "keyctl_read_alloc returned invalid array size");
		free(krbuf);
		return PAM_SYSTEM_ERR;
	}

	/* Count valid sessions by checking if PIDs are alive */
	for (i = 0; i < (bufsz / sizeof(key_serial_t)); i++) {
		pid_t pid;

		/* Extract PID from key description
		 * This will fail for expired/revoked keys */
		if (session_key_to_pid(krbuf[i], &pid) == 0) {
			/* Check if process is still alive */
			if (kill(pid, 0) == 0 || errno == EPERM) {
				/* Process exists (or we lack permission to signal it) */
				cnt++;
			} else {
				/* Process is dead - unlink the key */
				keyctl_unlink(krbuf[i], session_keyring);
			}
		} else {
			/* Key is expired/revoked or malformed - unlink it */
			keyctl_unlink(krbuf[i], session_keyring);
		}
	}

	free(krbuf);
	*count_out = cnt;
	return PAM_SUCCESS;
}
