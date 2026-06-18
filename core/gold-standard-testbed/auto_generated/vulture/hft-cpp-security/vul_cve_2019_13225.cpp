// Vulnerable: VUL-CVE-2019-13225
}

      if (IS_NOT_NULL(Else)) {
        len += SIZE_OP_JUMP;
...

      if (IS_NOT_NULL(Else)) {
        len += SIZE_OP_JUMP;
        tlen = compile_length_tree(Else, reg);
        if (tlen < 0) return tlen;
...
...

        r = compile_tree(Else, reg, env);
      }
