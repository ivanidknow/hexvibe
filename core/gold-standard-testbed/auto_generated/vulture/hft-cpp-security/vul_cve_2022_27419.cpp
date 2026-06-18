// Vulnerable: VUL-CVE-2022-27419
// Combine signal if exactly three repeats were found
    if (n_rows == 3) {
        uint8_t *b = bitbuffer->bb[bitbuffer->num_rows];
        for (int i = 0; i < 11; ++i) {
            // The majority bit count wins
...
                    (b_rows[2][i] & b_rows[0][i]);
        }
        bitbuffer->bits_per_row[bitbuffer->num_rows] = 88;
        bitbuffer->num_rows += 1;
    }
