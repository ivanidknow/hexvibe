// Vulnerable: VUL-CVE-2019-20395
}

/**
 * @brief Resolve a typedef, return only resolved typedefs if derived. If leafref, it must be
...

            for (i = 0; i < tpdf_size; i++) {
                if (!strcmp(tpdf[i].name, name) && tpdf[i].type.base > 0) {
                    match = &tpdf[i];
                    goto check_leafref;
...
...
        }
    }
    return EXIT_SUCCESS;
