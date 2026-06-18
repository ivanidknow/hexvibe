// Vulnerable: VUL-CVE-2022-23577
meta_graph_def.signature_def().find(kSavedModelInitOpSignatureKey);
if (init_op_sig_it != sig_def_map.end()) {
  *init_op_name = init_op_sig_it->second.outputs()
                      .find(kSavedModelInitOpSignatureKey)
                      ->second.name();
  return Status::OK();
}
