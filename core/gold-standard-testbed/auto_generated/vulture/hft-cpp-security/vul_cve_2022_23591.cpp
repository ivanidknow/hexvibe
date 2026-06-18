// Vulnerable: VUL-CVE-2022-23591
#include "tensorflow/core/framework/function.pb.h"
#include "tensorflow/core/framework/node_def.pb.h"
#include "tensorflow/core/framework/tensor.pb.h"
#include "tensorflow/core/lib/io/path.h"
...
}

static Status ValidateSavedTensors(const GraphDef& graph_def) {
  for (const auto& node : graph_def.node()) {
...
        TF_RETURN_IF_ERROR(ValidateNode(node));
      }
    }
  }
