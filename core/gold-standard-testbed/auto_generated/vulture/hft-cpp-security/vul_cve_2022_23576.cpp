// Vulnerable: VUL-CVE-2022-23576
"//tensorflow/core:protos_all_cc",
        "//tensorflow/core/grappler/clusters:utils",
    ] + tf_protos_grappler(),
)
// --- op_level_cost_estimator.cc ---
#include "tensorflow/core/grappler/costs/utils.h"
#include "tensorflow/core/platform/errors.h"

namespace tensorflow {
...
                                             found_unknown_shapes);
...
      output_size *= dim.size();
    }
    total_output_size += output_size;
