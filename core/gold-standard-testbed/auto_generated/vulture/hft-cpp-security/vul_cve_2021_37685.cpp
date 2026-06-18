// Vulnerable: VUL-CVE-2021-37685
}
TF_LITE_ENSURE(context, axis <= input_dims.size);

TfLiteIntArray* output_dims = TfLiteIntArrayCreate(input_dims.size + 1);
