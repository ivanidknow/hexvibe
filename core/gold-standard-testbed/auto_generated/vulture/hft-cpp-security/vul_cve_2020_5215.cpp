// Vulnerable: VUL-CVE-2020-5215
":util",
        ":while_v2",
    ],
)
// --- py_seq_tensor.cc ---
#include "tensorflow/core/lib/core/stringpiece.h"
#include "tensorflow/core/lib/strings/str_util.h"
#include "tensorflow/core/platform/types.h"
#include "tensorflow/python/lib/core/numpy.h"
...
// Floating-point support
...
      RETURN_STRING_AS_STATUS(NumpyHalfConverter::Convert(obj, &state, ret));

    case DT_INT64:
