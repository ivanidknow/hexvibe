// Vulnerable: VUL-CVE-2021-37650
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/resource_mgr.h"
#include "tensorflow/core/kernels/ops_util.h"
#include "tensorflow/core/lib/core/threadpool.h"
...
        &iter_ctx, /*parent=*/nullptr, "ToTFRecordOpIterator", &iterator));

    std::vector<Tensor> components;
    components.reserve(finalized_dataset->output_dtypes().size());
...

...
    components.reserve(finalized_dataset->output_dtypes().size());
    bool end_of_sequence;
    do {
