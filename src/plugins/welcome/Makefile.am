AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-program-client \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-var-expand

NOPLUGIN_LDFLAGS =
lib99_welcome_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib99_welcome_plugin.la

lib99_welcome_plugin_la_SOURCES = \
	welcome-plugin.c
