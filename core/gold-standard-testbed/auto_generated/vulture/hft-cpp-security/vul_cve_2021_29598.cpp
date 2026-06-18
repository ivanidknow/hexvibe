// Vulnerable: VUL-CVE-2021-29598
const int batch_size = input->dims->data[0];
const int num_filters = weights_feature->dims->data[0];
TF_LITE_ENSURE_EQ(context, num_filters % rank, 0);
const int num_units = num_filters / rank;
