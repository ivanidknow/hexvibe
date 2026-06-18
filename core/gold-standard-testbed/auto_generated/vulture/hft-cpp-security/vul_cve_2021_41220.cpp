// Vulnerable: VUL-CVE-2021-41220
const Tensor& instance_key) {
    if (group_size.dims() > 0) {
      return errors::Internal("Unexpected dimensions on input group_size, got ",
                              group_size.shape().DebugString());
    }
    if (group_key.dims() > 0) {
...
    }
    if (group_key.dims() > 0) {
      return errors::Internal("Unexpected dimensions on input group_key, got ",
                              group_key.shape().DebugString());
...
    Tensor group_assignment = c->input(2);
// --- collective_ops_test.py ---
class CollectiveOpsV3Test(test.TestCase, parameterized.TestCase):
