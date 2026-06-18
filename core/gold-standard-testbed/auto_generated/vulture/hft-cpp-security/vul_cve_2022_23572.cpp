// Vulnerable: VUL-CVE-2022-23572
// TODO(mdan): This is also done at graph construction. Run only here instead?
const auto ret = full_type::SpecializeType(attrs_, op_def);
DCHECK(ret.status().ok()) << "while instantiating types: " << ret.status();
ret_types_ = ret.ValueOrDie();
