pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = pop3-login

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth-client \
	-I$(top_srcdir)/src/lib-sasl \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-login \
	-I$(top_srcdir)/src/login-common \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-pop3 \
	-I$(top_srcdir)/src/lib-var-expand \
	$(BINARY_CFLAGS)

pop3_login_LDADD = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT) \
	$(SSL_LIBS) \
	$(BINARY_LDFLAGS)

pop3_login_DEPENDENCIES = \
	$(LIBDOVECOT_LOGIN) \
	$(LIBDOVECOT_DEPS)

pop3_login_SOURCES = \
	client.c \
	client-authenticate.c \
	pop3-login-settings.c \
	pop3-proxy.c

noinst_HEADERS = \
	client.h \
	client-authenticate.h \
	pop3-proxy.h
