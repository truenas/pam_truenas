pamdir = @pamdir@

pam_LTLIBRARIES = pam_truenas.la

pam_truenas_la_SOURCES = \
	pam_truenas_auth.c \
	pam_truenas_ctx.c \
	pam_truenas_session.c \
	pam_truenas.c \
	pam_truenas.h \
	keyring.c \
	keyring.h \
	error.c \
	error.h \
	json.c \
	json.h \
	tally.c \
	tally.h \
	kr_session.c \
	kr_session.h \
	utils.c
pam_truenas_la_CFLAGS = $(JANSSON_CFLAGS) -fPIC
pam_truenas_la_LDFLAGS = -module -avoid-version -shared
pam_truenas_la_LIBADD = $(JANSSON_LIBS) -lkeyutils -lpam -lpthread -ltruenas_scram -ltruenas_pwenc -luuid -lcrypto
