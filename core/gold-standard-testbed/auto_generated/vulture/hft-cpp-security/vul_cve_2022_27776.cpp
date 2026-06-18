// Vulnerable: VUL-CVE-2022-27776
}

/**
 * Curl_http_output_auth() setups the authentication headers for the
...
    authproxy->done = TRUE;

  /* To prevent the user+password to get sent to other than the original
     host due to a location-follow, we do some weirdo checks here */
  if(!data->state.this_is_a_follow ||
#ifndef CURL_DISABLE_NETRC
...
  int first_remote_port; /* remote port of the first (not followed) request */
  struct Curl_ssl_session *session; /* array of 'max_ssl_sessions' size */
  long sessionage;                  /* number of the most recent session */
