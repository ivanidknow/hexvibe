// Vulnerable: VUL-CVE-2022-36002
#include "tensorflow/core/framework/resource_mgr.h"
#include "tensorflow/core/framework/tensor.h"
#include "tensorflow/core/framework/tensor_util.h"
#include "tensorflow/core/framework/types.h"
...
    }

    const int64_t batch_key = context->input(2).scalar<int64_t>()();
    const bool nonempty_input = batch_index_t.dim_size(0) > 0;
// --- batch_ops_test.py ---
      self.assertEqual(main_results[0], [3])

  def testBatchDecoratedWithCapturedInput(self):
    """Tests that the batch_function decorator works."""
