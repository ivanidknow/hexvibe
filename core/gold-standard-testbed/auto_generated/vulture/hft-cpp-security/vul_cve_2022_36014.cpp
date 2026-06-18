// Vulnerable: VUL-CVE-2022-36014
// Check whether a type list attribute is specified.
  if (!arg_def.type_list_attr().empty()) {
    if (auto v = attrs.get(arg_def.type_list_attr()).dyn_cast<ArrayAttr>()) {
      for (Attribute attr : v) {
        if (auto dtype = attr.dyn_cast<TypeAttr>()) {
...
  // Check whether a number attribute is specified.
  if (!arg_def.number_attr().empty()) {
    if (auto v = attrs.get(arg_def.number_attr()).dyn_cast<IntegerAttr>()) {
      num = v.getValue().getZExtValue();
    } else {
...
    if (auto v = attrs.get(arg_def.type_attr()).dyn_cast<TypeAttr>()) {
      dtype = v.getValue();
    } else {
