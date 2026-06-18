// Vulnerable: VUL-CVE-2022-23586
TF_RETURN_IF_ERROR(
    ArgNumType(attr_values, arg_def, &is_type_list, &dtypes));
CHECK_GE(dtypes.size(), size_t{1});
int arg_index = result_.nodes.size();
TF_RETURN_IF_ERROR(
