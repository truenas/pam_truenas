// SPDX-License-Identifier: LGPL-3.0-or-later

#include "includes.h"
#include "keyring.h"
#include "tally.h"
#include <pwd.h>

#define DEFAULT_PWNAM_BUFSZ 4096

/**
 * Parse a string containing an unsigned integer value.
 *
 * @param[in] str_in String containing the number to parse
 * @param[out] val_out Parsed unsigned integer value (if successful)
 * @param[in] max_val Maximum acceptable value (0 means no limit beyond UINT_MAX)
 *
 * @return true if all characters were converted successfully, false otherwise
 *         On error, errno is set to:
 *         - EINVAL if string is NULL or not a valid number
 *         - ERANGE if value is too large
 */
bool ptn_parse_uint(const char *str_in, unsigned int *val_out, unsigned int max_val)
{
	uint64_t lval;
	char *end = NULL;

	if (str_in == NULL || val_out == NULL) {
		errno = EINVAL;
		return false;
	}

	// strtoul requires explicitly setting errno to zero
	errno = 0;
	lval = strtoul(str_in, &end, 0);
	if (errno != 0) {
		// errno already set by strtoul
		return false;
	}

	/*
	 * If there were no digits at all then end == str_in
	 * If all characters were digits then *end will be '\0'
	 * Otherwise *end will be the first invalid character.
	 */
	if ((end == str_in) || (*end != '\0')) {
		errno = EINVAL;
		return false;
	}

	// Check against UINT_MAX first
	if (lval > UINT_MAX) {
		errno = ERANGE;
		return false;
	}

	// If max_val is non-zero, check against the specified maximum
	if (max_val != 0 && lval > max_val) {
		errno = ERANGE;
		return false;
	}

	*val_out = (unsigned int)lval;
	return true;
}

/*
 * Look up provided username via NSS and return a malloced string
 * containing its canonicalized form. If caller specifies non-NULL
 * for uid_out or gid_out then those values will be passed out
 * of the function.
 *
 * Canonicalization of usernames is required from a security standpoint.
 * NSS and PAM modules may have multiple mechanisms of identifying the
 * same user. For example "bob@truenas.com" is the same as "TRUENAS\\bob"
 * and "TRUENAS\\Bob" when viewed through nss_winbind. Using getpwnam_r
 * pw_name field for updating the PAM_USER value and for internal
 * session tracking and failure tracking ensures that restrictions cannot
 * be bypassed by tweaking the username slightly.
 *
 * returns NULL on error with errno set
 */
char *canonicalize_username(const char *uname_in, uid_t *uid_out, gid_t *gid_out)
{
	char *uname_out = NULL;
	char *pwbuf = NULL;
	struct passwd pwd;
	struct passwd *pwd_result;
	int res;

	if (uname_in == NULL) {
		// glibc nscd will return -1 without errno set
		// if we pass in NULL username, so we'll exit early
		errno = EINVAL;
		return NULL;
	}

	pwbuf = malloc(DEFAULT_PWNAM_BUFSZ);
	if (pwbuf == NULL) {
		return NULL;
	}

	res = getpwnam_r(uname_in, &pwd, pwbuf, DEFAULT_PWNAM_BUFSZ, &pwd_result);
	if (res == ERANGE) {
		// The passwd entry was too large to fit in our default
		// buffer size. This is incredibly unusual. We only try once
		// with a large buffer because it's not really conceivable
		// that a valid passwd entry would have more than 16384 bytes
		//
		// libzfs breaks above 2048 and samba and many applications
		// use 8192 as an upper bound
		char *tmpbuf = NULL;
		tmpbuf = realloc(pwbuf, DEFAULT_PWNAM_BUFSZ * 4);

		if (tmpbuf == NULL) {
			free(pwbuf);
			return NULL;
		}

		pwbuf = tmpbuf;
		res = getpwnam_r(uname_in, &pwd, pwbuf, DEFAULT_PWNAM_BUFSZ * 4, &pwd_result);
	}

	if (res == 0) {
		if (pwd_result != NULL) {
			// malloc failure here will be caught by caller
			// since it's our return value
			uname_out = strdup(pwd_result->pw_name);
			if (uid_out != NULL)
				*uid_out = pwd_result->pw_uid;
			if (gid_out != NULL)
				*gid_out = pwd_result->pw_gid;
		} else {
			// username not found
			errno = ENOENT;
		}
	} else {
		errno = res;
	}

	free(pwbuf);

	return uname_out;
}
