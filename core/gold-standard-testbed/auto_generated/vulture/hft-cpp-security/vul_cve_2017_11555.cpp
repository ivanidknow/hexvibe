// Vulnerable: VUL-CVE-2017-11555
for (auto key : m->keys()) {
  Expression_Ptr ex_key = key->perform(this);
  Expression_Ptr ex_val = m->at(key)->perform(this);
  *mm << std::make_pair(ex_key, ex_val);
}
