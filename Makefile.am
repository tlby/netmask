AM_CFLAGS = -Wall
bin_PROGRAMS = netmask
netmask_SOURCES = main.c netmask.c netmask.h errors.c errors.h
netmask_CPPFLAGS = $(CHECK_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS)
netmask_CFLAGS = $(AM_CFLAGS) $(CHECK_CFLAGS) $(CODE_COVERAGE_CFLAGS)
netmask_LDADD = $(CHECK_LIBS) $(CODE_COVERAGE_LIBS)

info_TEXINFOS = netmask.texi
netmask_TEXINFOS = gpl.texi

man_MANS = netmask.1
EXTRA_DIST = $(man_MANS) testscript $(srcdir)/tests/*

TESTS = testscript

CODE_COVERAGE_IGNORE_PATTERN = "/usr/include/*" "*_test.c" --ignore-errors unused
include $(top_srcdir)/aminclude_static.am

clean-local: code-coverage-clean

distclean-local: code-coverage-dist-clean

repo-clean: maintainer-clean
	git clean -Xfd

repo-release: distcheck
	gpg --armor --detach-sign $(PACKAGE)-$(VERSION).tar.gz
