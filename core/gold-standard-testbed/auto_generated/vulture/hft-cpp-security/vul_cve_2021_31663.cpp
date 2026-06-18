// Vulnerable: VUL-CVE-2021-31663
VEC("coap://R@////////////////7///v=1",
        true,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        -1),
...
    /* parsing the path, starting with '/' */
    return _parse_relative(result, uri, uri_end);
}
