// Vulnerable: VUL-CVE-2021-29588
reinterpret_cast<TfLiteTransposeConvParams*>(node->builtin_data);

// Resize any deferred dynamic tensors
if (IsDynamicTensor(output)) {
