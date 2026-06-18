# Vulnerable: VUL-CVE-2012-1163
SET(PACKAGE_VERSION_MAJOR "0")
SET(PACKAGE_VERSION_MINOR "10")
SET(PACKAGE_VERSION_PATCH "0")
SET(VERSION "${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR}.${PACKAGE_VERSION_PATCH}")
SET(PACKAGE_VERSION ${VERSION})
// --- NEWS ---
0.10 [2010/03/18]
// --- THANKS ---
Stephen Bryant <steve@bawue.de>
Tarmo Pikaro <tapika@yahoo.com>
// --- configure.ac ---
...
AC_INIT([libzip],[0.10],[libzip-discuss@nih.at])
AC_CONFIG_SRCDIR([lib/zip_add.c])
AC_CONFIG_HEADERS([config.h])
