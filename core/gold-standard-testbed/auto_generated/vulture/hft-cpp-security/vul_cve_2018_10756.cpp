// Vulnerable: VUL-CVE-2018-10756
{
    tr_variant const* v;
    tr_variant sorted;
    size_t childIndex;
    bool isVisited;
...
        qsort(tmp, n, sizeof(struct KeyIndex), compareKeyIndex);

        tr_variantInitDict(&node->sorted, n);

        for (size_t i = 0; i < n; ++i)
...
        tr_free(node->sorted.val.l.vals);
    }
}
