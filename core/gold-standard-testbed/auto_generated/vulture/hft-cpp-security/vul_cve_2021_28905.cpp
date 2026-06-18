// Vulnerable: VUL-CVE-2021-28905
lyxml_free(ctx, root.child);
    }
    lys_node_free(retval, NULL, 0);

    return NULL;
...
error:
    lyxml_free(ctx, dflt);
    lys_node_free(retval, NULL, 0);
    return NULL;
}
...
                        lys_node_free(siter, NULL, 0);
                    }
                    *pp = NULL;
