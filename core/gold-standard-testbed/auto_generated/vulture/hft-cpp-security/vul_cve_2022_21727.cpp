// Vulnerable: VUL-CVE-2022-21727
#include "tensorflow/core/framework/types.pb.h"
#include "tensorflow/core/lib/core/errors.h"
#include "tensorflow/core/util/mirror_pad_mode.h"
#include "tensorflow/core/util/padding.h"
...
                                       axis);
      }
      const int minmax_rank = (axis == -1) ? 0 : 1;
      TF_RETURN_IF_ERROR(shape_inference::UnchangedShape(c));
...
      if (axis != -1) {
...


@test_util.run_all_in_graph_and_eager_modes
