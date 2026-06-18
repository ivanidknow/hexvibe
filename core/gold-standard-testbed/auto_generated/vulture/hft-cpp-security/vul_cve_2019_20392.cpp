// Vulnerable: VUL-CVE-2019-20392
trg_mod = lys_node_module(parent);
        }
        rc = lys_getnext_data(trg_mod, context_node, source, sour_len, LYS_LEAF | LYS_LEAFLIST, &src_node);
        if (rc) {
            LOGVAL(ctx, LYE_NORESOLV, LY_VLOG_LYS, parent, "leafref predicate", path-parsed);
...
                trg_mod = lys_node_module(parent);
            }
            rc = lys_getnext_data(trg_mod, dst_node, dest, dest_len, LYS_CONTAINER | LYS_LIST | LYS_LEAF, &dst_node);
            if (rc) {
                LOGVAL(ctx, LYE_NORESOLV, LY_VLOG_LYS, parent, "leafref predicate", path_key_expr);
...
    while ((node = lys_getnext(node, parent, mod, 0))) {
        if (!type || (node->nodetype & type)) {
            /* module check */
