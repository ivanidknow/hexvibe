// Vulnerable: VUL-CVE-2022-23570
#include "tensorflow/core/framework/types.h"
#include "tensorflow/core/platform/statusor.h"

namespace tensorflow {
...
      if (arg->type_id() == TFT_VAR) {
        const auto* attr = attrs.Find(arg->s());
        DCHECK(attr != nullptr);
        if (attr->value_case() == AttrValue::kList) {
          const auto& attr_list = attr->list();
