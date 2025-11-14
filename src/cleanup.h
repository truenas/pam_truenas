// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef _CLEANUP_H_
#define _CLEANUP_H_

/**
 * Secure Memory Cleanup Utilities
 *
 * This header provides memory-wiping macros and inline functions for
 * securely clearing sensitive data (passwords, keys, authentication tokens)
 * from memory. These utilities prevent sensitive data from lingering in
 * memory where it could be recovered through memory dumps or swap files.
 *
 * The implementations are derived from pam_inline.h and use either
 * memset_explicit() or explicit_bzero() to ensure the compiler cannot
 * optimize away the memory clearing operations.
 *
 * Key macros:
 * - pam_overwrite_array(): Clear an array (compile-time array check)
 * - pam_overwrite_object(): Clear a pointed-to object (compile-time pointer check)
 * - pam_overwrite_string(): Clear a null-terminated string
 */

/* Following are from pam_inline.h */
#ifdef HAVE_MEMSET_EXPLICIT
static inline void pam_overwrite_n(void *ptr, size_t len)
{
	if (ptr)
		memset_explicit(ptr, '\0', len);
}
#else
static inline void pam_overwrite_n(void *ptr, size_t len)
{
	if (ptr)
		explicit_bzero(ptr, len);
}
#endif

# define PAM_IS_SAME_TYPE(x_, y_) \
	__builtin_types_compatible_p(__typeof__(x_), __typeof__(y_))

/*
 * Evaluates to
 * - a syntax error if the argument is 0,
 * 0, otherwise.
 */
#define PAM_FAIL_BUILD_ON_ZERO(e_)	(sizeof(int[-1 + 2 * !!(e_)]) * 0)

/*
 * Evaluates to
 * 1, if the given type is known to be a non-array type
 * 0, otherwise.
 */
#define PAM_IS_NOT_ARRAY(a_)		PAM_IS_SAME_TYPE((a_), &(a_)[0])

/*
 * Evaluates to
 * - a syntax error if the argument is not an array,
 * 0, otherwise.
 */
#define PAM_MUST_BE_ARRAY(a_)		PAM_FAIL_BUILD_ON_ZERO(!PAM_IS_NOT_ARRAY(a_))
/*
 * Evaluates to
 * - a syntax error if the argument is an array,
 * 0, otherwise.
 */
#define PAM_MUST_NOT_BE_ARRAY(a_)	PAM_FAIL_BUILD_ON_ZERO(PAM_IS_NOT_ARRAY(a_))

#define pam_overwrite_array(x) pam_overwrite_n(x, sizeof(x) + PAM_MUST_BE_ARRAY(x))
#define pam_overwrite_object(x) pam_overwrite_n(x, sizeof(*(x)) + PAM_MUST_NOT_BE_ARRAY(x))
#define pam_overwrite_string(x)                      \
do {                                                 \
	char *xx__ = (x) + PAM_MUST_NOT_BE_ARRAY(x); \
	if (xx__)                                    \
		pam_overwrite_n(xx__, strlen(xx__)); \
} while(0)

/* end pam_inline.h */

#endif /* _CLEANUP_H_ */
