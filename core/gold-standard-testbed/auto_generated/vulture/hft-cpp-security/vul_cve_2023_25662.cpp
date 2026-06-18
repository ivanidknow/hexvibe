// Vulnerable: VUL-CVE-2023-25662
#include "tensorflow/core/framework/types.pb.h"
#include "tensorflow/core/lib/core/errors.h"
#include "tensorflow/core/platform/types.h"
#include "tensorflow/core/util/mirror_pad_mode.h"
...
        return shape_inference::UnknownShape(c);
      }

      if (hypothesis_shape_t->NumElements() != truth_shape_t->NumElements()) {
        return errors::InvalidArgument(
...
...


if __name__ == "__main__":
