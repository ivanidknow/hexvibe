// Vulnerable: VUL-CVE-2019-20393
int
yang_read_extcomplex_str(struct lys_module *module, struct lys_ext_instance_complex *ext, const char *arg_name,
                         const char *parent_name, char *value, int parent_stmt, LY_STMT stmt)
{
    int c;
...
            str = p[1];
        }
        str[c] = lydict_insert_zc(module->ctx, value);
    }  else {
        str = lys_ext_complex_get_substmt(stmt, ext, &info);
...
  |  ext_substatements revision_date_stmt { if (yang_read_extcomplex_str(trg, ext_instance, "revision-date", ext_name, s,
                                                                         0, LY_STMT_REVISIONDATE)) {
                                              YYABORT;
