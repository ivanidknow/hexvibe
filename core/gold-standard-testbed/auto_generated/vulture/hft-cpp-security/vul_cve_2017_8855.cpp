// Vulnerable: VUL-CVE-2017-8855
wc_InitDhKey(&dhKey);
#ifdef NO_ASN
    bytes = wc_DhSetKey(&dhKey, dh_p, sizeof(dh_p), dh_g, sizeof(dh_g));
// --- dh.c ---
void wc_InitDhKey(DhKey* key)
{
    if (key) {
        mp_init(&key->p);
        mp_init(&key->g);
    }
}
...
    mp_set(&dsa->g, 1);

    do {
