noinst_LTLIBRARIES = libstorage_exmdbc.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-sasl/ \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/list \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-var-expand \
	-I$(top_srcdir)/../gromox/include \
	-I$(srcdir) \
	$(libHX_CFLAGS)

AM_CXXFLAGS = -std=c++20

libstorage_exmdbc_la_LDFLAGS = -L/home/sergey/grommunio/gromox/.libs
libstorage_exmdbc_la_LIBADD = \
	-lstdc++ \
	-lgromox_rpc \
	-lgromox_common \
	-lgromox_mapi \
	-lgromox_exrpc

libstorage_exmdbc_la_SOURCES = \
	exmdbc-list.c \
	exmdbc-sync.c \
	exmdbc-attribute.c \
	exmdbc-msgmap.c \
	exmdbc-mail.c \
	exmdbc-mail-fetch.c \
	exmdbc-mailbox.c \
	exmdbc-save.c \
	exmdbc-search.c \
	exmdbc-storage.c \
	exmdb_client_c.cpp

headers = \
	exmdbc-list.h \
	exmdbc-sync.h \
	exmdbc-attribute.h \
	exmdbc-msgmap.h \
	exmdbc-mail.h \
	exmdbc-mailbox.h \
	exmdbc-search.h \
	exmdbc-storage.h \
	exmdb_client_c.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
