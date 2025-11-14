// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef _TALLY_H_
#define _TALLY_H_

#include <keyutils.h>
#include "pam_truenas.h"

#define TALLY_FLAG_RHOST	0x00000001
#define TALLY_FLAG_TTY		0x00000002


/*
 * The following constants are for enforcing
 * SRG-OS-000329-GPOS-00128
 *
 * The operating system must automatically lock an
 * account when three unsuccessful logon attempts in
 * 15 minutes occur.
 *
 * RHEL STIG guidelines permit a 15 minute unlock
 * interval.
 */
#define MAX_FAILURE 3
#define FAIL_INTERVAL 900  // 15 minutes in seconds
#define UNLOCK_INTERVAL 900
#define TALLY_LOCK_KEY	"tally_lock"

typedef struct {
	char source[NAME_MAX];  // PAM_RHOST or PAM_TTY
	uint32_t flags;		// flags related to entry
} ptn_tally_t;

/* Error message type for keyring operations */
typedef ptn_err_t tally_err_msg_t;

int check_tally(pam_tn_ctx_t *ctx, bool *is_locked);
int write_tally(pam_tn_ctx_t *ctx);
int reset_tally(pam_tn_ctx_t *ctx);

#endif /* _TALLY_H_ */
