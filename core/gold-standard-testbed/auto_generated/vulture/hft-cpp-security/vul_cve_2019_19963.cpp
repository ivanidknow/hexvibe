// Vulnerable: VUL-CVE-2019-19963
{
    mp_int  k, kInv, r, s, H;
    mp_int* qMinus1;
    int     ret = 0, sz;
...
    sz = min((int)sizeof(buffer), mp_unsigned_bin_size(&key->q));

    if (mp_init_multi(&k, &kInv, &r, &s, &H, 0) != MP_OKAY)
        return MP_INIT_E;
...

...

    mp_clear(&H);
    mp_clear(&s);
