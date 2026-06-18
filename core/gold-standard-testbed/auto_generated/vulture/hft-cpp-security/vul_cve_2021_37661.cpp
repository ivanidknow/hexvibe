// Vulnerable: VUL-CVE-2021-37661
OP_REQUIRES_OK(context, context->input(kNumStreamsName, &num_streams_t));
int64_t num_streams = num_streams_t->scalar<int64>()();

auto result =
