// SPDX-License-Identifier: LGPL-3.0-or-later

#include "error.h"
#include <stdio.h>
#include <stdarg.h>

void _ptn_set_error(ptn_err_t *error, const char *fmt, const char *location, ...)
{
	va_list args;
	int offset;

	if (!error || !fmt) {
		return;
	}

	va_start(args, location);
	offset = vsnprintf(error->message, sizeof(error->message), fmt, args);
	va_end(args);

	if (offset > 0 && (size_t)offset < sizeof(error->message) - 1) {
		snprintf(error->message + offset, sizeof(error->message) - offset,
			" [%s]", location);
	}
}
