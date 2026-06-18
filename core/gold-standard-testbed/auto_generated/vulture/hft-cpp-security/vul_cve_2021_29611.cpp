// Vulnerable: VUL-CVE-2021-29611
#include "tensorflow/core/kernels/reshape_util.h"
#include "tensorflow/core/lib/gtl/inlined_vector.h"

namespace tensorflow {
...

  void Compute(OpKernelContext* context) override {
    ReshapeSparseTensor<Device>(context, context->input(0), context->input(1),
                                context->input(2), 0 /* output indices index */,
