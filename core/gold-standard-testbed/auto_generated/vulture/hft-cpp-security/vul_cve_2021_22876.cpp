// Vulnerable: VUL-CVE-2021-22876
test2071 test2072 test2073 test2074 test2075 test2076 test2077 \
test2078 \
test2080 \
test2100 \
\
// --- transfer.c ---
      if(data->set.http_auto_referer) {
        /* We are asked to automatically set the previous URL as the referer
           when we get the next URL. We pick the ->url field, which may or may
...
        }
...
          return CURLE_OUT_OF_MEMORY;
        data->state.referer_alloc = TRUE; /* yes, free this later */
      }
