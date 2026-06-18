// Vulnerable: VUL-CVE-2020-11958
memmove(buf, tok, copy);
        shift_ptrs_and_fpos(buf - bot);
        delete [] bot;
        bot = buf;
...
    }

    if (!read(free)) {
        eof = lim;
