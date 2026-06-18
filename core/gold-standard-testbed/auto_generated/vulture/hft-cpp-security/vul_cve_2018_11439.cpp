// Vulnerable: VUL-CVE-2018-11439
)

if(NOT WIN32)
  set(unicode_SRCS
    toolkit/unicode.cpp
  )
endif()

if(HAVE_ZLIB_SOURCE)
  set(zlib_SRCS
...
...

  void testIterator()
  {
