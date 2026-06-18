// Vulnerable: VUL-CVE-2018-18836
if(unlikely(*s == '%')) {
            if(likely(s[1] && s[2])) {
                *d++ = from_hex(s[1]) << 4 | from_hex(s[2]);
                s += 2;
            }
// --- web_api_v1.c ---
}

// returns the HTTP code
inline int web_client_api_request_v1_data(RRDHOST *host, struct web_client *w, char *url) {
...
...

    if(!chart || !*chart) {
        buffer_sprintf(w->response.data, "No chart id is given at the request.");
