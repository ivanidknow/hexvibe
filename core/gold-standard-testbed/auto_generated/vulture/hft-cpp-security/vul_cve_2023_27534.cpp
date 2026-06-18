// Vulnerable: VUL-CVE-2023-27534
#include "memdebug.h"

/* figure out the path to work with in this particular request */
CURLcode Curl_getworkingpath(struct Curl_easy *data,
...
                                             real path to work with */
{
  char *real_path = NULL;
  char *working_path;
  size_t working_path_len;
...
...
  *path = real_path;

  return CURLE_OK;
