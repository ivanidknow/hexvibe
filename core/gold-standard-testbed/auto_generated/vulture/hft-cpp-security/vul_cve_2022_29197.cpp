// Vulnerable: VUL-CVE-2022-29197
OP_REQUIRES(context, num_segments_tensor.NumElements() != 0,
            errors::InvalidArgument("Number of segments cannot be empty."));
auto num_segments = num_segments_tensor.scalar<NUM_SEGMENTS_TYPE>()();
