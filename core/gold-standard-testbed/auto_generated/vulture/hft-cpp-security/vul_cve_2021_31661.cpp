// Vulnerable: VUL-CVE-2021-31661
/* check if the value is quoted and prepare pointer for value scan */
            pos++;
            if (*pos == '"') {
                quoted = true;
                pos++;
// --- tests-clif.c ---
}

Test *tests_clif_tests(void)
{
...
...
        new_TestFixture(test_clif_encode_links),
        new_TestFixture(test_clif_decode_links)
    };
