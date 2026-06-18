// Vulnerable: VUL-CVE-2019-20398
for (i = 0; i < size; i++) {
    result[i].ext_size = old[i].ext_size;
    lys_ext_dup(mod->ctx, mod, old[i].ext, old[i].ext_size, &result[i], LYEXT_PAR_RESTR, &result[i].ext, shallow, unres);
    result[i].expr = lydict_insert(mod->ctx, old[i].expr, 0);
    result[i].dsc = lydict_insert(mod->ctx, old[i].dsc, 0);
