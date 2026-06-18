// Vulnerable: VUL-CVE-2022-29204
auto num_segments = num_segments_tensor.scalar<NUM_SEGMENTS_TYPE>()();

OP_REQUIRES(context, num_segments > 0,
            errors::InvalidArgument("Number of segments must be positive"));
OP_REQUIRES(context, segment_dims != 0,
            errors::InvalidArgument("Segment_id cannot have rank 0"));
