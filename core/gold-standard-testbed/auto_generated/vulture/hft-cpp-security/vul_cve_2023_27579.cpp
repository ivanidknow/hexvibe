// Vulnerable: VUL-CVE-2023-27579
auto input_channel = input->dims->data[3];
auto filter_input_channel = filter->dims->data[3];
TF_LITE_ENSURE_EQ(context, input_channel % filter_input_channel, 0);
data->groups = input_channel / filter_input_channel;
