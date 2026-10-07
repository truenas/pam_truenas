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

#define KEY_TYPE_USER "user"

/* Largest payload pack_session() produces: every string at its maximum */
#define KR_SESS_PAYLOAD_MAX (sizeof(kr_sess_hdr_t) + \
			     sizeof(((kr_sess_t *)NULL)->cred.name) + \
			     sizeof(kr_pam_item_t) + SECURITY_LABEL_MAX + \
			     sizeof(((kr_sess_t *)NULL)->json_data))

static char *
put_string(char *p, const char *str, size_t size)
{
	/* str is NUL-terminated within its size-byte array */
	size_t len = strnlen(str, size - 1);

	memcpy(p, str, len);
	p[len] = '\0';
	return p + len + 1;
}

/**
 * @brief Serialize a session into its keyring payload, see kr_sess_hdr_t
 *
 * @param[out] buf - at least KR_SESS_PAYLOAD_MAX bytes
 * @return payload length
 */
static size_t
pack_session(const kr_sess_t *sess, char *buf)
{
	kr_sess_hdr_t hdr;
	const char *sec = "";
	char *p = buf + sizeof(hdr);

	memset(&hdr, 0, sizeof(hdr));
	hdr.version = KR_SESS_VERSION;
	hdr.flags = sess->flags;
	hdr.creation = sess->creation;
	memcpy(hdr.session_id, sess->session_id, sizeof(hdr.session_id));
	hdr.pid = sess->pid;
	hdr.sid = sess->sid;
	hdr.origin_family = sess->origin_family;
	hdr.uid = sess->cred.uid;
	hdr.gid = sess->cred.gid;

	switch (sess->origin_family) {
	case AF_UNIX:
		hdr.origin.unix_origin.pid = sess->origin.unix_origin.pid;
		hdr.origin.unix_origin.uid = sess->origin.unix_origin.uid;
		hdr.origin.unix_origin.gid = sess->origin.unix_origin.gid;
		hdr.origin.unix_origin.loginuid = sess->origin.unix_origin.loginuid;
		sec = sess->origin.unix_origin.sec;
		break;
	case AF_INET:
	case AF_INET6:
		hdr.origin.tcp_origin = sess->origin.tcp_origin;
		break;
	}

	memcpy(buf, &hdr, sizeof(hdr));
	p = put_string(p, sess->cred.name, sizeof(sess->cred.name));
	p = put_string(p, sess->pam_item.service, sizeof(sess->pam_item.service));
	p = put_string(p, sess->pam_item.ruser, sizeof(sess->pam_item.ruser));
	p = put_string(p, sess->pam_item.rhost, sizeof(sess->pam_item.rhost));
	p = put_string(p, sess->pam_item.tty, sizeof(sess->pam_item.tty));
	p = put_string(p, sec, SECURITY_LABEL_MAX);
	p = put_string(p, sess->json_data, sizeof(sess->json_data));

	return p - buf;
}

/* Returns the position after the string, or NULL if p is NULL or the string
 * is unterminated or longer than pack_session() writes */
static const char *
get_string(const char *p, const char *end, char *dst, size_t size)
{
	size_t len;

	if (p == NULL) {
		return NULL;
	}

	len = strnlen(p, end - p);
	if ((len == (size_t)(end - p)) || (len >= size)) {
		return NULL;
	}

	memcpy(dst, p, len);
	dst[len] = '\0';
	return p + len + 1;
}

/**
 * @brief Parse a session keyring payload, see kr_sess_hdr_t
 *
 * @return 0 on success, -1 if the payload is not a session
 */
static int
unpack_session(const char *buf, size_t len, kr_sess_t *sess)
{
	kr_sess_hdr_t hdr;
	char sec[SECURITY_LABEL_MAX];
	const char *p, *end = buf + len;

	if (len < sizeof(hdr)) {
		return -1;
	}

	memcpy(&hdr, buf, sizeof(hdr));
	if (hdr.version != KR_SESS_VERSION) {
		return -1;
	}

	memset(sess, 0, sizeof(*sess));
	sess->creation = hdr.creation;
	memcpy(sess->session_id, hdr.session_id, sizeof(sess->session_id));
	sess->pid = hdr.pid;
	sess->sid = hdr.sid;
	sess->flags = hdr.flags;
	sess->origin_family = hdr.origin_family;
	sess->cred.uid = hdr.uid;
	sess->cred.gid = hdr.gid;

	p = get_string(buf + sizeof(hdr), end, sess->cred.name, sizeof(sess->cred.name));
	p = get_string(p, end, sess->pam_item.service, sizeof(sess->pam_item.service));
	p = get_string(p, end, sess->pam_item.ruser, sizeof(sess->pam_item.ruser));
	p = get_string(p, end, sess->pam_item.rhost, sizeof(sess->pam_item.rhost));
	p = get_string(p, end, sess->pam_item.tty, sizeof(sess->pam_item.tty));
	p = get_string(p, end, sec, sizeof(sec));
	p = get_string(p, end, sess->json_data, sizeof(sess->json_data));
	if (p != end) {
		return -1;
	}

	switch (hdr.origin_family) {
	case AF_UNIX:
		sess->origin.unix_origin.pid = hdr.origin.unix_origin.pid;
		sess->origin.unix_origin.uid = hdr.origin.unix_origin.uid;
		sess->origin.unix_origin.gid = hdr.origin.unix_origin.gid;
		sess->origin.unix_origin.loginuid = hdr.origin.unix_origin.loginuid;
		strlcpy(sess->origin.unix_origin.sec, sec, sizeof(sess->origin.unix_origin.sec));
		break;
	case AF_INET:
	case AF_INET6:
		sess->origin.tcp_origin = hdr.origin.tcp_origin;
		break;
	}

	return 0;
}

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
	char payload[KR_SESS_PAYLOAD_MAX];
	char *uuid_pos;
	size_t prefix_len = strlen(PAM_TN_ENV_SES_UUID);
	size_t uuid_len, payload_len;
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

	payload_len = pack_session(sess, payload);

	/* Add the session data to the keyring using "UUID:pid" as description */
	key_id = add_key(KEY_TYPE_USER, key_desc, payload, payload_len, session_keyring);
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
 * @brief Read and parse a session key
 *
 * Fails for revoked and expired keys -- a closed session is revoked -- and
 * for anything in the SESSIONS keyring that is not a session.
 *
 * @return 0 on success, -1 on error
 */
static int
read_session_key(key_serial_t key_id, kr_sess_t *sess)
{
	char buf[KR_SESS_PAYLOAD_MAX];
	long len;

	/* keyctl_read() returns the full payload size, even if it is larger
	 * than the buffer */
	len = keyctl_read(key_id, buf, sizeof(buf));
	if ((len <= 0) || (len > (long)sizeof(buf))) {
		return -1;
	}

	return unpack_session(buf, len, sess);
}

/**
 * @brief Check whether the process that opened a session still exists
 */
static bool
session_process_alive(pid_t pid)
{
	if (pid <= 0) {
		/* kill() would address a process group */
		return false;
	}

	/* EPERM: the process exists but we lack permission to signal it */
	return (kill(pid, 0) == 0) || (errno == EPERM);
}

static void
copy_pam_item(pam_handle_t *pamh, int item_type, char *buf, size_t bufsz)
{
	const char *val = NULL;

	if ((pam_get_item(pamh, item_type, (const void **)&val) == PAM_SUCCESS) &&
	    (val != NULL)) {
		strlcpy(buf, val, bufsz);
	}
}

void
ptn_kr_get_pam_items(pam_handle_t *pamh, kr_pam_item_t *items)
{
	memset(items, 0, sizeof(*items));

	copy_pam_item(pamh, PAM_SERVICE, items->service, sizeof(items->service));
	copy_pam_item(pamh, PAM_RUSER, items->ruser, sizeof(items->ruser));
	copy_pam_item(pamh, PAM_RHOST, items->rhost, sizeof(items->rhost));
	copy_pam_item(pamh, PAM_TTY, items->tty, sizeof(items->tty));
}

/**
 * @brief Find a session that this process opened on another PAM handle
 *
 * Samba opens and closes each SMB session with its own pam_start() /
 * pam_end() pair (smb_pam_claim_session() and smb_pam_close_session()), so
 * the key serial cached on the opening handle is gone by the time the
 * session is closed.
 *
 * Such a session is identified by the process that opened it, PAM_SERVICE
 * and PAM_TTY: an application that does this names each session with a
 * distinct tty (Samba uses "smb/<session id>"). PAM_RHOST is not compared;
 * Samba takes it from the session's first channel, which multichannel can
 * replace.
 *
 * A session without a tty is never matched. It cannot be told apart from the
 * other sessions of its process -- middlewared holds many, one PAM handle
 * each -- so it is only closed on the handle that opened it.
 */
key_serial_t
ptn_kr_find_session(pam_handle_t *pamh, key_serial_t session_keyring,
		    kr_sess_t *sess_out)
{
	kr_pam_item_t items;
	key_serial_t *krbuf = NULL;
	key_serial_t found = -1;
	pid_t pid = getpid();
	long bufsz;
	size_t i;

	ptn_kr_get_pam_items(pamh, &items);
	if ((items.tty[0] == '\0') || (session_keyring <= 0)) {
		return -1;
	}

	bufsz = keyctl_read_alloc(session_keyring, (void **)&krbuf);
	if ((bufsz == -1) || ((bufsz % sizeof(key_serial_t)) != 0)) {
		free(krbuf);
		return -1;
	}

	for (i = 0; i < (bufsz / sizeof(key_serial_t)); i++) {
		if (read_session_key(krbuf[i], sess_out) != 0) {
			continue;
		}

		/* The stored strings come from the keyring: bound the compare */
		if ((sess_out->pid == pid) &&
		    (strncmp(sess_out->pam_item.service, items.service,
			     sizeof(items.service)) == 0) &&
		    (strncmp(sess_out->pam_item.tty, items.tty,
			     sizeof(items.tty)) == 0)) {
			found = krbuf[i];
			break;
		}
	}

	free(krbuf);

	if (found == -1) {
		memset(sess_out, 0, sizeof(*sess_out));
	}

	return found;
}

/**
 * @brief Get count of active sessions for a user
 *
 * Every key in the SESSIONS keyring is checked, and keys that are revoked
 * (closed), expired or malformed, or whose process has exited, are unlinked.
 * Session keys never expire and are charged to the key quota of uid 0, so a
 * session that is never closed would otherwise stay until reboot.
 */
int
ptn_kr_get_session_count(key_serial_t session_keyring, size_t *count_out, kr_err_msg_t *err)
{
	key_serial_t *krbuf = NULL;
	size_t i, nkeys, cnt = 0;
	long bufsz;
	kr_sess_t sess;

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

	nkeys = bufsz / sizeof(key_serial_t);
	for (i = 0; i < nkeys; i++) {
		if ((read_session_key(krbuf[i], &sess) != 0) ||
		    !session_process_alive(sess.pid)) {
			keyctl_unlink(krbuf[i], session_keyring);
			continue;
		}

		cnt++;
	}

	free(krbuf);
	*count_out = cnt;
	return PAM_SUCCESS;
}
