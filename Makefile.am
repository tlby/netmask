AM_CFLAGS = -Wall
bin_PROGRAMS = netmask
netmask_SOURCES = main.c netmask.c netmask.h errors.c errors.h u128.h
netmask_CPPFLAGS = $(CHECK_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS)
netmask_CFLAGS = $(AM_CFLAGS) $(CHECK_CFLAGS) $(CODE_COVERAGE_CFLAGS)
netmask_LDADD = $(CHECK_LIBS) $(CODE_COVERAGE_LIBS)

check_PROGRAMS = nm_test
nm_test_SOURCES = nm_test.c netmask.c netmask.h errors.c errors.h u128.h
nm_test_CPPFLAGS = $(CHECK_CPPFLAGS) $(CODE_COVERAGE_CPPFLAGS)
nm_test_CFLAGS = $(AM_CFLAGS) $(CHECK_CFLAGS) $(CODE_COVERAGE_CFLAGS)
nm_test_LDADD = $(CHECK_LIBS) $(CODE_COVERAGE_LIBS)
nm_test_LDFLAGS = -Wl,--wrap=getaddrinfo

info_TEXINFOS = netmask.texi
netmask_TEXINFOS = gpl.texi

man_MANS = netmask.1
EXTRA_DIST = $(man_MANS) testscript $(srcdir)/tests/*

TESTS = testscript nm_test

CODE_COVERAGE_IGNORE_PATTERN = "/usr/include/*" "*_test.c" --ignore-errors unused
include $(top_srcdir)/aminclude_static.am

clean-local: code-coverage-clean

distclean-local: code-coverage-dist-clean

repo-clean: maintainer-clean
	git clean -Xfd

repo-release: distcheck
	gpg --armor --detach-sign $(PACKAGE)-$(VERSION).tar.gz
