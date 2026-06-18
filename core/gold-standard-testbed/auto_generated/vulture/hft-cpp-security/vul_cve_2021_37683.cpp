// Vulnerable: VUL-CVE-2021-37683
GetOutputSafe(context, node, kOutputTensor, &output));

  if (output->type == kTfLiteFloat32 || output->type == kTfLiteInt32) {
    EvalDiv<kernel_type>(context, node, params, data, input1, input2, output);
  } else if (output->type == kTfLiteUInt8) {
...
    EvalDiv<kernel_type>(context, node, params, data, input1, input2, output);
  } else if (output->type == kTfLiteUInt8) {
    TF_LITE_ENSURE_OK(
        context, EvalQuantized<kernel_type>(context, node, params, data, input1,
...
...
  }

  return kTfLiteOk;
