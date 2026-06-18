// Vulnerable: VUL-CVE-2013-0868
if (len1 > limit)
                        continue;
                    len[i] = len0 + len1;
                    bits[i] = (s->bits[0][y] << len1) + s->bits[p][u];
...
                    if (len2 > limit1)
                        continue;
                    len[i] = len0 + len1 + len2;
                    bits[i] = (code << len2) + s->bits[2][r & 255];
...
    GetBitContext gb;
...
        init_vlc(&s->vlc[i], VLC_BITS, 256, s->len[i], 1, 1,
                 s->bits[i], 4, 4, 0);
    }
