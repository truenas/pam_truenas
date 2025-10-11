// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef _PAM_TRUENAS_ERROR_H_
#define _PAM_TRUENAS_ERROR_H_


typedef struct pam_truenas_error_info {
	char message[1024];
} ptn_err_t;

/*
 * @brief set error message in error struct with location info
 *
 * @param[in]	error - error struct to set message in (may be NULL)
 * @param[in]	fmt - printf-style format string
 * @param[in]	location - location string
 * @param[in]	... - format arguments
 */
void _ptn_set_error(ptn_err_t *error, const char *fmt,
		    const char *location, ...);

#define __stringify(x) #x
#define __stringify2(x) __stringify(x)
#define __location__ __FILE__ ":" __stringify2(__LINE__)

#define ptn_set_error(error, fmt, ...) \
	_ptn_set_error(error, fmt, __location__, ##__VA_ARGS__)


#endif /* _PAM_TRUENAS_ERROR_H_ */
