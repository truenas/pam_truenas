// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef _KEYRING_H_
#define _KEYRING_H_

#include <keyutils.h>
#include "pam_truenas.h"

/*
 * Keyring format
 *
 * persistent-keyring:uid=0
 * ├── user key: TRUENAS_SCRAM_PLUS_SERVER_BINDING (SCRAM-PLUS channel binding)
 * └── keyring: PAM_TRUENAS
 *  ├── keyring: alice
 *  │   ├── keyring: SESSIONS
 *  │   ├── keyring: API_KEYS
 *  │   └── keyring: FAILLOG
 *  ├── keyring: bob
 *  │   ├── keyring: SESSIONS
 *  │   ├── keyring: API_KEYS
 *  │   └── keyring: FAILLOG
 *  └── keyring: charlie
 *      ├── keyring: SESSIONS
 *      ├── keyring: API_KEYS
 *      └── keyring: FAILLOG
 */

/* Error message type for keyring operations */
typedef ptn_err_t keyring_err_msg_t;

/* Get the PAM keyring serial (persistent-keyring:uid=0 -> PAM_TRUENAS)*/
key_serial_t keyring_get_pam_keyring(void);

/*
 * Get the serial for the keyring for the specified username */
key_serial_t keyring_get_truenas_user_keyring(key_serial_t pkey, const char *username);
key_serial_t keyring_get_api_key_keyring(key_serial_t user_keyring);
key_serial_t keyring_get_session_keyring(key_serial_t user_keyring);
key_serial_t keyring_get_tally(key_serial_t user_keyring);

/* Load server auth data from keyring and populate scram_auth_data structure */
int load_server_auth_data_from_keyring(pam_tn_ctx_t *pam_ctx,
				       keyring_err_msg_t *error_msg);

/*
 * Load the server-wide SCRAM channel binding (precomputed tls-server-end-point
 * value) that middlewared stores in the uid=0 persistent keyring. Returns 0 and
 * fills *binding_out (caller releases it with crypto_datum_clear) when the slot
 * exists, -ENOENT when it is absent, or another -errno on a read failure.
 */
int load_server_channel_binding(crypto_datum_t *binding_out);

#endif /* _KEYRING_H_ */
