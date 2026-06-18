// Vulnerable: VUL-CVE-2021-41200
const Tensor* tmp;
    OP_REQUIRES_OK(ctx, ctx->input("logdir", &tmp));
    const string logdir = tmp->scalar<tstring>()();
    OP_REQUIRES_OK(ctx, ctx->input("max_queue", &tmp));
...
    const string logdir = tmp->scalar<tstring>()();
    OP_REQUIRES_OK(ctx, ctx->input("max_queue", &tmp));
    const int32_t max_queue = tmp->scalar<int32>()();
    OP_REQUIRES_OK(ctx, ctx->input("flush_millis", &tmp));
...
    const int32_t max_queue = tmp->scalar<int32>()();
...


class FileWriterCacheTest(test.TestCase):
