# Vulnerable: VUL-CVE-2023-31124
OPTION (CARES_BUILD_CONTAINER_TESTS "Build and run container tests (implies CARES_BUILD_TESTS, Linux only)" OFF)
OPTION (CARES_BUILD_TOOLS "Build tools"                                                          ON)

# Tests require static to be enabled on Windows to be able to access otherwise hidden symbols
...


find_file(CARES_RANDOM_FILE urandom /dev)
mark_as_advanced(CARES_RANDOM_FILE)


...
    ]
)
if test -n "$CARES_RANDOM_FILE" && test X"$CARES_RANDOM_FILE" != Xno ; then
