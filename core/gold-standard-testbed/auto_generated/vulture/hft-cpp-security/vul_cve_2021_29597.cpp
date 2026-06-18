// Vulnerable: VUL-CVE-2021-29597
int final_dim_size = (input_size->data[dim + 1] + paddings_data[dim * 2] +
                      paddings_data[dim * 2 + 1]);
TF_LITE_ENSURE_EQ(context, final_dim_size % block_shape[dim], 0);
output_size->data[dim + 1] = final_dim_size / block_shape[dim];
