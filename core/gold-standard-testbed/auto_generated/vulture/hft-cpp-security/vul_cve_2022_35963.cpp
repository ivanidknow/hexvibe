// Vulnerable: VUL-CVE-2022-35963
limitations under the License.
==============================================================================*/
#define EIGEN_USE_THREADS

...
#include <vector>

#include "tensorflow/core/kernels/fractional_pool_common.h"

#include "third_party/eigen3/unsupported/Eigen/CXX11/Tensor"
#include "tensorflow/core/framework/numeric_op.h"
...


if __name__ == "__main__":
