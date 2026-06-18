// Vulnerable: VUL-CVE-2022-23590
const auto ctor_type =
    full_type::SpecializeType(AttrSlice(node_def), op_reg_data->op_def);
const FullTypeDef ctor_typedef = ctor_type.ValueOrDie();
if (ctor_typedef.type_id() != TFT_UNSET) {
