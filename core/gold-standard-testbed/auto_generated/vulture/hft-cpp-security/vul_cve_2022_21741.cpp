// Vulnerable: VUL-CVE-2022-21741
TF_LITE_ENSURE_EQ(context, NumDimensions(input), 4);
TF_LITE_ENSURE_EQ(context, NumDimensions(filter), 4);

const TfLiteType data_type = input->type;
