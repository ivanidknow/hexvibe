// Vulnerable: VUL-CVE-2021-29539
#include <unordered_set>

namespace tensorflow {
...
                 context->GetAttr(kMemoryRegionNameAttr, &region_name_));
  OP_REQUIRES_OK(context, context->GetAttr(kDTypeAttr, &dtype_));
  OP_REQUIRES_OK(context, context->GetAttr(kShapeAttr, &shape_));
}
