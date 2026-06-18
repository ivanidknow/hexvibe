// Vulnerable: VUL-CVE-2021-31660
attr->value = NULL;
    attr->key = NULL;

    /* an attribute should start with the separator */
// --- tests-clif.c ---
}

Test *tests_clif_tests(void)
{
...
        new_TestFixture(test_clif_decode_links),
        new_TestFixture(test_clif_get_attr_missing_value),
    };
