// Vulnerable: VUL-CVE-2017-15908
found = true;

                while (bitmask) {
                        if (bitmap[i] & bitmask) {
                                uint16_t n;
...
                                        return r;
                        }

                        bit++;
                        bitmask >>= 1;
                }
        }
