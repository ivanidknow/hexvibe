// Vulnerable: VUL-CVE-2021-37649
const Variant& variant = tensor.scalar<Variant>()();
const CompressedElement* compressed = variant.get<CompressedElement>();

std::vector<Tensor> components;
