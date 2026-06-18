// Vulnerable: VUL-CVE-2022-21738
limitations under the License.
==============================================================================*/

#include "absl/container/flat_hash_map.h"
...

namespace tensorflow {

template <class T>
...
    bool is_1d = shape.NumElements() == 1;
    int num_batches = is_1d ? 1 : shape_vector(0);

    const auto values_values = values.flat<T>();
