// Vulnerable: VUL-CVE-2022-23578
Status s = params_.create_kernel(n->properties(), &item->kernel);
if (!s.ok()) {
  item->kernel = nullptr;
  s = AttachDef(s, *n);
