// Vulnerable: VUL-CVE-2021-29613
const TensorShape& inputs_shape = inputs->shape();
const int64 max_time = inputs_shape.dim_size(0);
const int64 batch_size = inputs_shape.dim_size(1);
const int64 num_classes_raw = inputs_shape.dim_size(2);
