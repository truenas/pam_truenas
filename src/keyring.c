// SPDX-License-Identifier: LGPL-3.0-or-later

#include "keyring.h"
#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* man (7) sem_overview maximum name length for named semaphore */
typedef char semname_t[NAME_MAX - 4];

/* Keyring semaphore management code
 * ---------------------------------
 * We treat the keyring description as a unique identifier. This
 * exposes some risk of race when creating the per-user keyring
 * layout. To help avoid this risk we employ named semaphores that
 * are held specifically when creating the new keyrings and are
 * deleted once they are created.
 */
static
sem_t *get_keyring_semaphore(const char *name)
{
	semname_t sname;
	sem_t *out;
	snprintf(sname, sizeof(sname), "/" MODULE_NAME "-%s", name);

	out = sem_open(sname, O_CREAT, 0600, 1);
	if (out == SEM_FAILED) {
		return NULL;
	}

	return out;
}

static
void keyring_semaphore_cleanup(sem_t *krsem, const char *name, bool unlink)
{
	semname_t sname;
	sem_post(krsem);
	sem_close(krsem);

	if (unlink) {
		snprintf(sname, sizeof(sname), "/" MODULE_NAME "-%s", name);
		sem_unlink(sname);
	}
}

/**
 * function to atomically get or create a keyring with the specified name
 * inside the specified keyring. It's technically possible to create multiple
 * keys with the same description in the same keyring; however, there is not
 * a convenient method to get all instances matching a particular description.
 * keyctl_search() will return the most recently added. This means we need
 * to use a synchronization primitive if must go from the get to the create
 * portion of this function. Since it may be called internally by multiple
 * threads in the same process (if there are multiple PAM handles) or by
 * multiple processes, we're currently using named semaphores here.
 */
static key_serial_t get_or_create_keyring(key_serial_t pkey, const char *name)
{
	key_serial_t found, created;
	sem_t *sem;

	found = keyctl_search(pkey, "keyring", name, 0);
	if ((found > 0) || ((found == -1) && (errno != ENOKEY))) {
		// We either found the key or had an unexpected error
		return found;
	}

	// key with "name" was not found so we'll acquire semaphore
	sem = get_keyring_semaphore(name);
	if (sem == NULL) {
		// errno set by sem_open()
		return -1;
	}

	sem_wait(sem);
	// search for key a second time. Another process or thread
	// may have created the key between our first check and us
	// acquiring the semaphore
	found = keyctl_search(pkey, "keyring", name, 0);
	if ((found > 0) || ((found == -1) && (errno != ENOKEY))) {
		// We either found the key or had an unexpected error
		// Keep semaphore around in hopes someone can fix
		keyring_semaphore_cleanup(sem, name, false);
		return found;
	}

	created = add_key("keyring", name, NULL, 0, pkey);
	if (created == -1) {
		keyring_semaphore_cleanup(sem, name, false);
		return created;
	}

	// Once we've definitely created the target keyring
	// we can safely unlink the named semaphore
	keyring_semaphore_cleanup(sem, name, true);
	return created;
}

/* This function retrieves the top-level "PAM_TRUENAS" keyring which
 * resides in the persistent keyring of UID 0
 */
key_serial_t keyring_get_pam_keyring(void)
{
	key_serial_t pkey;
	key_serial_t pam_kr;

	pkey = keyctl_get_persistent(0, KEY_SPEC_PROCESS_KEYRING);
	if (pkey == -1) {
		return pkey;
	}

	/* Get or create the PAM_TRUENAS keyring */
	pam_kr = get_or_create_keyring(pkey, PAM_KEYRING_NAME);
	return pam_kr;
}

/* This function retrieves the per-user from the specified keyring. If
 * the keyring is unspecified (set to zero), then the PAM_TRUENAS keyring
 * will be retrieved and used to get this keyring
 */
key_serial_t keyring_get_truenas_user_keyring(key_serial_t pkey, const char *username)
{
	key_serial_t pam_kr;

	if ((username == NULL) || (pkey < 0)) {
		errno = EINVAL;
		return -1;
	}

	if (pkey == 0) {
		/* Get the PAM_TRUENAS keyring if not provided */
		pam_kr = keyring_get_pam_keyring();
		if (pam_kr == -1) {
			return pam_kr;
		}
	} else {
		pam_kr = pkey;
	}

	/* Get or create the user keyring under PAM_TRUENAS */
	return get_or_create_keyring(pam_kr, username);
}

/* This function retrieves the API_KEYS from the specified user keyring */
key_serial_t keyring_get_api_key_keyring(key_serial_t user_keyring)
{
	if (user_keyring <= 0) {
		errno = EINVAL;
		return -1;
	}

	/* Get or create the API_KEYS keyring under the user keyring */
	return get_or_create_keyring(user_keyring, PAM_API_KEY_NAME);
}

/* This function retrieves the SESSIONS from the specified user keyring */
key_serial_t keyring_get_session_keyring(key_serial_t user_keyring)
{
	if (user_keyring <= 0) {
		errno = EINVAL;
		return -1;
	}

	/* Get or create the SESSIONS keyring under the user keyring */
	return get_or_create_keyring(user_keyring, PAM_SESSION_NAME);
}

/* This function retrieves the FAILLOG from the specified user keyring */
key_serial_t keyring_get_tally(key_serial_t user_keyring)
{
	if (user_keyring <= 0) {
		errno = EINVAL;
		return -1;
	}

	/* Get or create the FAILLOG keyring under the user keyring */
	return get_or_create_keyring(user_keyring, PAM_FAILLOG_NAME);
}

/* This function retrieves the encrypted API key information from
 * the specified user_keyring based on the information specified
 * in the provided scram_principal_t struct.
 */
static int get_encrypted_user_data(key_serial_t api_keys_kr,
				   scram_principal_t *principal,
				   pwenc_datum_t *data_out,
				   keyring_err_msg_t *error_msg)
{
	key_serial_t api_key;
	char api_key_desc[16];
	long key_size;

	if ((principal == NULL) || (data_out == NULL)) {
		ptn_set_error(error_msg, "Invalid arguments");
		return -EINVAL;
	}

	if (api_keys_kr <= 0) {
		ptn_set_error(error_msg, "Invalid user API keys keyring");
		return -EINVAL;
	}

	/* Now search for the specific API key within the API_KEYS keyring using dbid */
	snprintf(api_key_desc, sizeof(api_key_desc), "%u", principal->api_key_id);
	api_key = keyctl_search(api_keys_kr, "user", api_key_desc, 0);
	if (api_key == -1) {
		ptn_set_error(error_msg, "API key %u not found for user %s: %s",
			      principal->api_key_id,
			      principal->username, strerror(errno));
		return -ENOENT;
	}

	/* Get the size of the API key data */
	key_size = keyctl_read(api_key, NULL, 0);
	if (key_size <= 0) {
		ptn_set_error(error_msg, "Failed to get API key size: %s", strerror(errno));
		return -EIO;
	}

	/* Allocate buffer and read API key data. Ensure NULL-termination */
	data_out->size = key_size;
	data_out->data = calloc(1, data_out->size);
	if (data_out->data == NULL) {
		ptn_set_error(error_msg, "Memory allocation failed");
		return -ENOMEM;
	}

	if (keyctl_read(api_key, data_out->data, data_out->size) != key_size) {
		ptn_set_error(error_msg, "Failed to read API key data: %s", strerror(errno));
		return -EIO;
	}

	return 0;
}

/*
 * This function loads server authentication data from the PAM_TRUENAS keyring
 * based on populated authentication data in the pam_authenticate call (specifically
 * the PAM_USER set when initializing the context).
 *
 * The provided user for pam_truenas authentication is of the format:
 * bob:1 (where bob is the username and 1 is the API key id)
 *
 * or
 *
 * bob (where bob is the username and the API key id is implicitly zero). There is
 * future planned enhancement whereby API key zero is reserved for SCRAM auth data
 * for local user account password.
 *
 * Once the API key data is retrieved, it is decrypted using the general-purpose
 * truenas_pwenc library (https://github.com/truenas/truenas_pwenc).
 * and then loaded into memory.
 */
int load_server_auth_data_from_keyring(pam_tn_ctx_t *pam_ctx,
				       keyring_err_msg_t *error_msg)
{
	pwenc_ctx_t *pwenc_ctx = NULL;
	json_resp_t parse_result;
	pwenc_resp_t resp;
	pwenc_error_t pwenc_error = {0};
	pwenc_datum_t encrypted_data;
	pwenc_datum_t decrypted_data = {0};
	bool created;
	int ret;

	if ((pam_ctx == NULL) ||
	    (*pam_ctx->json_auth_data.principal.username == '\0')) {
		ptn_set_error(error_msg, "Invalid arguments");
		return -EINVAL;
	}

	ret = get_encrypted_user_data(pam_ctx->kr.api_keys_kr,
				      &pam_ctx->json_auth_data.principal,
				      &encrypted_data,
				      error_msg);
	if (ret != 0) {
		return ret;
	}

	resp = pwenc_init_context(NULL, 0, &pwenc_ctx, &created, &pwenc_error);
	if (resp != PWENC_SUCCESS) {
		ptn_set_error(error_msg, "Failed to init pwenc context: %s", pwenc_error.message);
		pwenc_free_context(pwenc_ctx);
		return -EIO;
	}

	resp = pwenc_decrypt(pwenc_ctx, &encrypted_data, &decrypted_data, &pwenc_error);
	pwenc_free_context(pwenc_ctx);
	if (resp != PWENC_SUCCESS) {
		ptn_set_error(error_msg, "Failed to decrypt API key data: %s", pwenc_error.message);
		pwenc_datum_free(&encrypted_data, false);
		return -EIO;
	}

	pwenc_datum_free(&encrypted_data, false);
	parse_result = parse_json_auth_data(&pam_ctx->json_auth_data, &decrypted_data, error_msg);
	pwenc_datum_free(&decrypted_data, true);

	switch(parse_result) {
	case JSON_E_SUCCESS:
		ret = 0;
		break;
	case JSON_E_NOT_FOUND:
		ret = -ENOENT;
		break;
	case JSON_E_CRYPTO:
	case JSON_E_PARSE:
	default:
		ret = -EINVAL;
		break;
	};

	return ret;
}
