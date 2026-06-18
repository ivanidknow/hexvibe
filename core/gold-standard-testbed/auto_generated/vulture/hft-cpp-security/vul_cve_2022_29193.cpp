// Vulnerable: VUL-CVE-2022-29193
const Tensor& tensor = c->input(1);
const Tensor& serialized_summary_metadata_tensor = c->input(2);

Summary s;
