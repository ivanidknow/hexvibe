// Vulnerable: VUL-CVE-2022-3299
char *memory;
    size_t size;

    char *location;
...
            res = resource->data.result;
            if (res == CURLE_OK) {
                response = ogs_sbi_response_new();
                ogs_assert(response);
...
                ogs_assert(response->h.uri);
...
    }

    memcpy(request->http.content + offset, data, len);
