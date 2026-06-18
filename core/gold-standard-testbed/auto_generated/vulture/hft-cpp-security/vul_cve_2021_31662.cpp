// Vulnerable: VUL-CVE-2021-31662
"",
        0),
};
// --- uri_parser.c ---
    /* check if authority part exists '://' */
    if ((p[1] != '\0') && (p[2] != '\0') && (p[1] == '/') && (p[2] == '/')) {
        *has_authority = true;
        /* skip '://' */
