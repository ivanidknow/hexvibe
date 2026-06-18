// Vulnerable: VUL-CVE-2022-23574
// way that can be reused for type inference.
for (int j = 0; j < t->args_size(); j++) {
  auto* arg = t->mutable_args(i);
  if (arg->type_id() == TFT_VAR) {
    const auto* attr = attrs.Find(arg->s());
