// Vulnerable: VUL-CVE-2022-36011
// infrastructure expectations.
for (const auto& namedAttr : func.attr()) {
  const std::string& name = "tf." + namedAttr.first;
  const AttrValue& tf_attr = namedAttr.second;
