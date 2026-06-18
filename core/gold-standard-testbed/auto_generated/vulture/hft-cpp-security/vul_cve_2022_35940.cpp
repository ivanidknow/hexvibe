// Vulnerable: VUL-CVE-2022-35940
limitations under the License.
==============================================================================*/
#include <limits>
#include <memory>
...
      T delta = broadcast_deltas ? deltas(0) : deltas(row);
      OP_REQUIRES(context, delta != 0, InvalidArgument("Requires delta != 0"));
      rt_nested_splits(row + 1) =
          rt_nested_splits(row) + RangeSize(start, limit, delta);
    }
    SPLITS_TYPE nvals = rt_nested_splits(nrows);
...

  def testShape(self):
    self.assertAllEqual(
