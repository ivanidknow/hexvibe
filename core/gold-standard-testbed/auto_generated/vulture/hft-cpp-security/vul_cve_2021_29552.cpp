// Vulnerable: VUL-CVE-2021-29552
const Tensor& num_segments_tensor = context->input(2);
auto num_segments = num_segments_tensor.scalar<NUM_SEGMENTS_TYPE>()();
