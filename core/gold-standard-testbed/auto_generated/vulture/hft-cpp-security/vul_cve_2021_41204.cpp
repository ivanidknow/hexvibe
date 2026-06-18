// Vulnerable: VUL-CVE-2021-41204
#include "tensorflow/core/framework/op_kernel.h"
#include "tensorflow/core/framework/types.h"
#include "tensorflow/core/graph/algorithm.h"
#include "tensorflow/core/graph/node_builder.h"
...
        shape_replacement_map) {
  if (n->IsConstant()) {
    return true;
  }
  if (MaybeReplaceShapeOp(n, shape_map, shape_replacement_map)) {
