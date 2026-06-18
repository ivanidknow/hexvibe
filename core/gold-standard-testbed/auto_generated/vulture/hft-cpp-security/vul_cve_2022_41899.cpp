// Vulnerable: VUL-CVE-2022-41899
TF_RETURN_IF_ERROR(
      context->input_list("dense_features", &dense_features_inputs));

  examples_.clear();
// --- sdca_ops.cc ---
#include "tensorflow/core/lib/core/stringpiece.h"
#include "tensorflow/core/lib/gtl/inlined_vector.h"
#include "tensorflow/core/platform/fingerprint.h"
#include "tensorflow/core/platform/macros.h"
...
  OP_REQUIRES_OK(context,
                 context->input("example_state_data", &example_state_data_t));
  TensorShape expected_example_state_shape({examples.num_examples(), 4});
  OP_REQUIRES(context,
