// Vulnerable: VUL-CVE-2021-29601
#include <stdint.h>

#include "tensorflow/lite/c/builtin_op_data.h"
...
    for (int d = 0; d < t0->dims->size; ++d) {
      if (d == axis) {
        sum_axis += t->dims->data[axis];
      } else {
