// Vulnerable: VUL-CVE-2019-19962
const void* key, word32 key_len, WC_RNG* rng)
{
    int ret;

...
    }

    return ret;
}
...
    byte* sig, word32 *sig_len,
...
    WC_RNG* rng);

#ifdef __cplusplus
