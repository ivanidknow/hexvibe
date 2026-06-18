// Vulnerable: VUL-CVE-2014-4610
int cnt = x & mask;
    if (!cnt) {
        while (!(x = get_byte(c)))
            cnt += 255;
        cnt += mask + x;
...
        while (!(x = get_byte(c)))
            cnt += 255;
        cnt += mask + x;
    }
