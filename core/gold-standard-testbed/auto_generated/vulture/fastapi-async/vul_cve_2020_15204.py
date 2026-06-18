# Vulnerable: VUL-CVE-2020-15204
from tensorflow.python.framework import ops
from tensorflow.python.framework import test_util
from tensorflow.python.ops import gen_math_ops
from tensorflow.python.ops import gen_string_ops
...
              preserve_short_sequences=False))


if __name__ == "__main__":
// --- session_ops.cc ---
#include <limits.h>
...
    int64 id = ctx->session_state()->GetNewId();
    TensorStore::TensorAndKey tk{val, id, requested_device()};
    OP_REQUIRES_OK(ctx, ctx->tensor_store()->AddTensor(name(), tk));
