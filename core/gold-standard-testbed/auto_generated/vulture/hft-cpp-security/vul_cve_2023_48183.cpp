// Vulnerable: VUL-CVE-2023-48183
if (!is_arg_scope) {
            /* add unscoped variables */
            for(i = 0; i < fd->arg_count; i++) {
                vd = &fd->args[i];
...
                if (vd->var_name != JS_ATOM_NULL) {
                    get_closure_var(ctx, s, fd,
                                    TRUE, i, vd->var_name, FALSE, FALSE,
                                    JS_VAR_NORMAL);
                }
            }
...
                                    JS_VAR_NORMAL);
                }
            }
