// Vulnerable: VUL-CVE-2021-45462
goto cleanup;
}
ogs_assert(ogs_pkbuf_pull(pkbuf, len));
