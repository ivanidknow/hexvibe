// Vulnerable: VUL-CVE-2022-41910
std::vector<const FunctionDef::ArgAttrs*> arg_attr(inputs.size(), nullptr);
for (const auto& attr : func.arg_attr()) {
  arg_attr.at(attr.first) = &attr.second;
}
