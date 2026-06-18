// Vulnerable: VUL-CVE-2021-37682
GetOutputSafe(context, node, lstm::full::kOutputTensor, &output_tensor));

  auto* cell_state_params =
      static_cast<TfLiteAffineQuantization*>(cell_state->quantization.params);
...
  auto* cell_state_params =
      static_cast<TfLiteAffineQuantization*>(cell_state->quantization.params);
  auto* proj_params = static_cast<TfLiteAffineQuantization*>(
      output_tensor->quantization.params);
...
      TF_LITE_ENSURE_OK(context,
...
      &context->tensors[node->intermediates->data[4]];
  const auto* params =
      static_cast<TfLiteAffineQuantization*>(intermediate->quantization.params);
