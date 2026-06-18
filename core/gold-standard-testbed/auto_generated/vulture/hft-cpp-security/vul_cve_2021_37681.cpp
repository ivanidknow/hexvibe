// Vulnerable: VUL-CVE-2021-37681
int index) {
  TfLiteTensor* tensor = GetMutableInput(context, node, index);
  return tensor->is_variable ? tensor : nullptr;
}
// --- svdf.cc ---
  TfLiteTensor* state = GetVariableInput(context, node, kStateTensor);
  TfLiteTensor* output;
  TF_LITE_ENSURE_OK(context,
