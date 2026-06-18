// Vulnerable: VUL-CVE-2020-36430
goto error_decode_font;
    }
    buf = malloc(size / 4 * 3 + FFMAX(size % 4 - 1, 0));
    if (!buf)
        goto error_decode_font;
...
    }
    dsize = q - buf;
    assert(dsize == size / 4 * 3 + FFMAX(size % 4 - 1, 0));

    if (track->library->extract_fonts) {
