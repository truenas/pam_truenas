// SPDX-License-Identifier: LGPL-3.0-or-later

#include "keyring.h"
#include "tally.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static
key_serial_t get_faillog(pam_tn_ctx_t *ctx)
{
	if (ctx->kr.user_kr == 0) {
		PAM_CTX_DEBUG(ctx, LOG_ERR, "User keyring is uninitialized");
		errno = ENOENT;
		return -1;
	}

	return keyring_get_tally(ctx->kr.user_kr);
}

#define NSEC_PER_SEC 1000000000

/* Write a failure entry to the FAILLOG keyring for the current user
 * based on PAM items
 */
int write_tally(pam_tn_ctx_t *ctx)
{
	int rv;
	const char *source;
	struct timespec now;
	char desc[42];
	key_serial_t faillog, key_id;
	long ret;
	ptn_tally_t tally = {0};
	const char *pam_user = NULL;

	pam_get_item(ctx->pamh, PAM_USER, (const void **)&pam_user);

	faillog = get_faillog(ctx);
	if (faillog == -1) {
		if (errno == ENOENT) {
			PAM_CTX_DEBUG(ctx, LOG_ERR,
				      "%s: User keyring is uninitialized",
				      PTN_STR_OR_UNKNOWN(pam_user));
			return PAM_ABORT;
		}

		PAM_CTX_DEBUG(ctx, LOG_ERR, "Failed to get faillog keyring");
		return PAM_ABORT;
	}

	if (clock_gettime(CLOCK_REALTIME, &now)) {
		PAM_CTX_DEBUG(ctx, LOG_ERR, "clock_gettime() failed: %s", strerror(errno));
		return PAM_SERVICE_ERR;
	}

	rv = pam_get_item(ctx->pamh, PAM_RHOST, (const void **)&source);
	if ((rv != PAM_SUCCESS) || (source == NULL)) {
		rv = pam_get_item(ctx->pamh, PAM_TTY, (const void **)&source);
		if ((rv != PAM_SUCCESS) || (source == NULL)) {
			source = "";
		} else {
			tally.flags |= TALLY_FLAG_TTY;
		}
	} else {
		tally.flags |= TALLY_FLAG_RHOST;
	}

	// Ensure that tv_nsec is less than 1 sec.
	while (now.tv_nsec > NSEC_PER_SEC) {
		now.tv_sec += 1;
		now.tv_nsec -= NSEC_PER_SEC;
	}

	strlcpy(tally.source, source, sizeof(tally.source));
	snprintf(desc, sizeof(desc), "%lu.%lu", now.tv_sec, now.tv_nsec);

	key_id = add_key("user", desc, &tally, sizeof(tally), faillog);
	if (key_id == -1) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			     "%s: add_key() failed to write tally entry: %s",
			     PTN_STR_OR_UNKNOWN(pam_user),
			     strerror(errno));
		return PAM_ABORT;
	}

	// Set the fail entry to automatically expire in FAIL_INTERVAL time
	ret = keyctl_set_timeout(key_id, FAIL_INTERVAL);
	if (ret == -1) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			     "%s: keyctl_set_timeout() failed to set timeout: %s",
			     PTN_STR_OR_UNKNOWN(pam_user), strerror(errno));
		keyctl_unlink(key_id, faillog);
		return PAM_ABORT;
	}

	return PAM_SUCCESS;
}

/*
 * is_tally_locked(), set_tally_lock(), and remove_tally_lock()
 * are functions that manage the per-user "locked" flag that gets
 * set inside the pre-user keyring. This key contains no
 * actual data, but its presence indicates that the account is
 * tally-locked. It has an expiry set on the key for 15 minutes
 * and once it expires the account is automatically unlocked.
 */
static
bool is_tally_locked(pam_tn_ctx_t *ctx)
{
	long rv;


	if (ctx->kr.user_kr == 0) {
		errno = EINVAL;
		return false;
	}

	rv = keyctl_search(ctx->kr.user_kr, "user", TALLY_LOCK_KEY, 0);
	return rv > 0 ? true : false;
}

static
bool set_tally_lock(pam_tn_ctx_t *ctx)
{
	key_serial_t lck;
	long rv;

	if (ctx->kr.user_kr == 0) {
		errno = EINVAL;
		return false;
	}

	lck = add_key("user", TALLY_LOCK_KEY, NULL, 0, ctx->kr.user_kr);
	if (lck == -1)
		return false;

	rv = keyctl_set_timeout(lck, UNLOCK_INTERVAL);
	if (rv == -1) {
		keyctl_unlink(lck, ctx->kr.user_kr);
		return false;
	}

	return true;
}

static
bool remove_tally_lock(pam_tn_ctx_t *ctx)
{
	long rv, lck;

	if (ctx->kr.user_kr == 0) {
		errno = EINVAL;
		return false;
	}

	lck = keyctl_search(ctx->kr.user_kr, "user", TALLY_LOCK_KEY, 0);
	if (lck == -1) {
		return false;
	}

	rv = keyctl_unlink(lck, ctx->kr.user_kr);
	return rv == 0 ? true : false;
}

/* This function checks whether the amount of login failure attempts
 * has exceed the maximum allowed for a given time period and sets
 * is_locked based on the results.
 */
int check_tally(pam_tn_ctx_t *ctx, bool *is_locked)
{
	long bufsz;
	key_serial_t *krbuf = NULL;
	size_t i, cnt = 0, total_keys;
	key_serial_t faillog;
	const char *pam_user = NULL;

	pam_get_item(ctx->pamh, PAM_USER, (const void **)&pam_user);

	faillog = get_faillog(ctx);
	if (faillog == -1) {
		if (errno == ENOKEY) {
			// faillog keyring doesn't exist
			// so it's by definition empty
			return PAM_SUCCESS;
		}

		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%s: failed to get faillog: %s",
			      PTN_STR_OR_UNKNOWN(pam_user),
			      strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	// short-circuit more expensive tests if we're locked right
	// now for the next < 15 minutes.
	if (is_tally_locked(ctx)) {
		*is_locked = true;
		return PAM_SUCCESS;
	}

	// read and allocate an array of key_serial_t serials for
	// keys in the faillog keyring
	bufsz = keyctl_read_alloc(faillog, (void **)&krbuf);
	if (bufsz == -1) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%s: keyctl_read_alloc() failed to read faillog: %s",
			      PTN_STR_OR_UNKNOWN(pam_user),
			      strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	if ((bufsz % sizeof(key_serial_t)) != 0) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%s: keyctl_read_alloc() returned invalid array size",
			      PTN_STR_OR_UNKNOWN(pam_user));
		free(krbuf);
		return PAM_SYSTEM_ERR;
	}

	total_keys = bufsz / sizeof(key_serial_t);
	if (total_keys < MAX_FAILURE) {
		free(krbuf);
		*is_locked = false;
		return PAM_SUCCESS;
	}

	for (i = 0; i < total_keys; i++) {
		long key_data_sz;
		// Simply getting buffer size required is sufficient to
		// determine whether a tally entry is expired
		key_data_sz = keyctl_read(krbuf[i], NULL, 0);
		if (key_data_sz == -1) {
			if ((errno == EKEYEXPIRED) ||
			    (errno == EKEYREVOKED)) {
				// Remove the expired / revoked key
				// to help slowly clean up the faillog
				keyctl_unlink(krbuf[i], faillog);
			} else if (errno != ENOKEY) {
				// Log a debug message for unexpected
				// error messages related to a faillog entry
				// ENOKEY can happen if TOCTOU (another thread / proc
				// already cleared the faillog entry after we built
				// array of keys.
				PAM_CTX_DEBUG(ctx, LOG_ERR,
					"%u: failed to read faillog entry: %s",
					krbuf[i], strerror(errno));
			}
		} else {
			cnt++;
		}
	}

	*is_locked = cnt >= MAX_FAILURE;
	if (*is_locked) {
		// failure to set here is non-fatal because next
		// caller will still fail due to key timeout on
		// faillog entries and we'll just pick up there
		if (!set_tally_lock(ctx)) {
			PAM_CTX_DEBUG(ctx, LOG_ERR,
				"%s: failed to set tally lock on uesr: %s",
			        PTN_STR_OR_UNKNOWN(pam_user),
				strerror(errno));
		}
	}
	free(krbuf);

	return PAM_SUCCESS;
}

/* Reset the FAILLOG tally. This is to be called after successful authentication */
int reset_tally(pam_tn_ctx_t *ctx)
{
	long rv;
	key_serial_t faillog;
	const char *pam_user = NULL;

	pam_get_item(ctx->pamh, PAM_USER, (const void **)&pam_user);

	faillog = get_faillog(ctx);
	if (faillog == -1) {
		if (errno == ENOKEY) {
			// faillog keyring doesn't exist
			// so it's by definition empty
			return PAM_SUCCESS;
		}

		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%s: failed to get faillog: %s",
			      PTN_STR_OR_UNKNOWN(pam_user),
			      strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	rv = keyctl_clear(faillog);
	if (rv) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%s: keyctl_clear() failed: %s",
			      PTN_STR_OR_UNKNOWN(pam_user),
			      strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	if (!remove_tally_lock(ctx)) {
		PAM_CTX_DEBUG(ctx, LOG_ERR,
			      "%s: failed to remove tally lock: %s",
			      PTN_STR_OR_UNKNOWN(pam_user),
			      strerror(errno));
		return PAM_SYSTEM_ERR;
	}

	return PAM_SUCCESS;
}
