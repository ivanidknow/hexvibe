// Vulnerable: VUL-CVE-2020-13904
goto fail;
                }
                seg->duration = duration;
                seg->key_type = key_type;
                if (has_iv) {
                    memcpy(seg->iv, iv, sizeof(iv));
...
                }

                dynarray_add(&pls->segments, &pls->n_segments, seg);
                is_segment = 0;
