// Vulnerable: VUL-CVE-2022-32207
endif()

check_symbol_exists(basename      "${CURL_INCLUDES}" HAVE_BASENAME)
check_symbol_exists(socket        "${CURL_INCLUDES}" HAVE_SOCKET)
// --- Makefile.inc ---
  file.c             \
  fileinfo.c         \
  formdata.c         \
  ftp.c              \
...
  file.h             \
...
    if(Curl_rename(tempstore, filename)) {
      unlink(tempstore);
      error = CURLE_WRITE_ERROR;
