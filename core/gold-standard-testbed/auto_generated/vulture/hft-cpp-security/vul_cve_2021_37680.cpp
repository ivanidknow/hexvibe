// Vulnerable: VUL-CVE-2021-37680
TF_LITE_ENSURE_EQ(context, NumDimensions(filter), 2);
const int batch_size = input_size / filter->dims->data[1];
const int num_units = filter->dims->data[0];
