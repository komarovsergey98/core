pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = log

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-var-expand \
	$(BINARY_CFLAGS)

log_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

log_DEPENDENCIES = $(LIBDOVECOT_DEPS)

log_SOURCES = \
	doveadm-connection.c \
	log-connection.c \
	log-settings.c \
	main.c

noinst_HEADERS = \
	doveadm-connection.h \
	log-connection.h
