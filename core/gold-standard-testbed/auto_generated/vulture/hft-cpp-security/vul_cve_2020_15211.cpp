// Vulnerable: VUL-CVE-2020-15211
const TfLiteTensor* GetOptionalInputTensor(const TfLiteContext* context,
                                           const TfLiteNode* node, int index) {
  const bool use_tensor = index < node->inputs->size &&
                          node->inputs->data[index] != kTfLiteOptionalTensor;
  if (use_tensor) {
    return GetMutableInput(context, node, index);
  }
  return nullptr;
}
