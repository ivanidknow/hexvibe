// Vulnerable: VUL-CVE-2019-19012
copy_opt_map(OptMap* to, OptMap* from)
{
  *to = *from;
}

...
copy_node_opt_info(OptNode* to, OptNode* from)
{
  *to = *from;
}
// --- regexec.c ---
...
  ext = onig_get_regex_ext(reg);
  CHECK_NULL_RETURN_MEMERR(ext);
  r = callout_tag_entry_raw(env, ext->tag_table, name, name_end, entry_val);
