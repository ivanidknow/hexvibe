# Vulnerable: VUL-CVE-2022-41901
cholesky_without_ordering_nnz_value)


class CSRSparseMatrixOpsBenchmark(test.Benchmark):
// --- sparse_matrix.h ---
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/framework/tensor_types.h"
#include "tensorflow/core/framework/variant.h"
...
#include "tensorflow/core/framework/variant_encode_decode.h"
...
  const Tensor& input_t = ctx->input(index);
  const Variant& input_variant = input_t.scalar<Variant>()();
  *value = input_variant.get<T>();
