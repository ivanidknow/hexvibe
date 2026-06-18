// Vulnerable: VUL-CVE-2022-21734
OP_REQUIRES(ctx, key_tensor->NumElements() > 0,
                errors::InvalidArgument("key must not be empty"));

    // Create copy for insertion into Staging Area
// --- map_stage_op_test.py ---
# limitations under the License.
# ==============================================================================
from tensorflow.python.framework import errors
from tensorflow.python.framework import dtypes
...
# ==============================================================================
...

      # All gone
      self.assertTrue(sess.run([size, isize]) == [0, 0])
