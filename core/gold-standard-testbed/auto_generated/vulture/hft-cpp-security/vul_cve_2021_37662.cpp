// Vulnerable: VUL-CVE-2021-37662
#include <limits>
#include <vector>

...
#include "tensorflow/core/kernels/boosted_trees/boosted_trees.pb.h"
#include "tensorflow/core/kernels/boosted_trees/tree_helper.h"
#include "tensorflow/core/platform/logging.h"

...
    const Tensor* node_id_range_t;
    OP_REQUIRES_OK(context, context->input("node_id_range", &node_id_range_t));
...
    std::vector<string> output_split_types;

    // TODO(tanzheny) parallelize the computation.
