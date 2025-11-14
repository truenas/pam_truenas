// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef _PAM_TRUENAS_H_
#define _PAM_TRUENAS_H_

#include "includes.h"
#include "error.h"
#include "kr_session.h"

enum ptn_request_tp {
	PAM_TRUENAS_AUTHENTICATE,
	PAM_TRUENAS_SETCRED,
	PAM_TRUENAS_OPEN_SESSION,
	PAM_TRUENAS_CLOSE_SESSION,
};

typedef struct pam_truenas_auth_data {
	scram_principal_t principal;
	scram_auth_data_t scram_data;
	time_t expiry;
} ptn_auth_data_t;

typedef struct {
	key_serial_t module_kr;		/* serial for pam_truenas module */
	key_serial_t user_kr;		/* serial for the user's personal keyring */
	key_serial_t api_keys_kr;	/* serial for the user's API_KEYS */
	key_serial_t sessions_kr;	/* serial for keyring containing user's SESSIONS */
} ptn_keyrings_t;

/**
 * PAM TrueNAS context structure
 *
 * This context is created in ptn_init_context() and stored in the PAM handle
 * via pam_set_data(). It persists across multiple calls to the PAM module
 * within the same PAM transaction. Cleanup is handled automatically by PAM
 * calling the registered cleanup callback (_ptn_cleanup_cb).
 */
typedef struct pam_truenas_ctx {
	pam_handle_t *pamh;             /* PAM handle for this transaction */
	uint32_t ctrl;                  /* Parsed configuration flags (PAM_TRUENAS_*) */
	uint32_t max_sessions;          /* Per-user session limit (0 = unlimited) */
	ptn_keyrings_t kr;		/* Struct containing keyrings relevant to pamh */
	ptn_auth_data_t json_auth_data; /* Decrypted auth data loaded from keyring */
	kr_sess_t session_info;         /* Session being opened/closed (session management only) */
	key_serial_t session_key_id;    /* Serial for session key in SESSIONS keyring */
} pam_tn_ctx_t;

/* Function declarations */
/* From pam_truenas_auth.c */
extern int ptn_do_plain_auth(pam_tn_ctx_t *pam_ctx, const char *username);
extern int ptn_do_scram_auth(pam_tn_ctx_t *pam_ctx, const char *username);

/* From pam_truenas_ctx.c */
extern uint32_t ptn_pam_parse(const pam_handle_t *pamh,
			      int flags,
			      int argc,
			      const char **argv,
			      uint32_t *psession_limit);

extern int ptn_init_context(pam_handle_t *pamh,
			    int flags,
			    int argc,
			    const char **argv,
			    enum ptn_request_tp type,
			    bool *pcreated,
			    pam_tn_ctx_t **ctx_p);

extern void ptn_cleanup_context(pam_tn_ctx_t *ctx);

/* From pam_truenas_session.c */
extern int ptn_open_session(pam_tn_ctx_t *pam_ctx);
extern int ptn_close_session(pam_tn_ctx_t *pam_ctx);

/* From pam_truenas.c */
extern bool pam_log_is_debug_enabled(uint32_t ctrl);

#endif /* _PAM_TRUENAS_H_ */
