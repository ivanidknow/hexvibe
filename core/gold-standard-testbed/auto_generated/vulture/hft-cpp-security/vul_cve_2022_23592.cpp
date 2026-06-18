// Vulnerable: VUL-CVE-2022-23592
if (node_t.type_id() != TFT_UNSET) {
  int ix = input_idx[i];
  DCHECK(ix < node_t.args_size())
      << "input " << i << " should have an output " << ix
      << " but instead only has " << node_t.args_size()
      << " outputs: " << node_t.DebugString();
  input_types.emplace_back(node_t.args(ix));
} else {
