// Vulnerable: VUL-CVE-2021-29602
int num_filter_channels = SizeOfDimension(filter, 3);
  int num_input_channels = SizeOfDimension(input, 3);
  TF_LITE_ENSURE_EQ(context, num_filter_channels % num_input_channels, 0);

...
  int num_input_channels = SizeOfDimension(input, 3);
  TF_LITE_ENSURE_EQ(context, num_filter_channels % num_input_channels, 0);

  *depth_multiplier = num_filter_channels / num_input_channels;
  return kTfLiteOk;
...
...
  const int batch_size = SizeOfDimension(input, 0);
  TfLiteTensor* input_quantized;
  TF_LITE_ENSURE_OK(context,
