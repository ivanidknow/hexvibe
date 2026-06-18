// Vulnerable: VUL-CVE-2022-35995
if (!has_sample_rate_attr_) {
      const Tensor& sample_rate_tensor = c->input(2);
      sample_rate = sample_rate_tensor.scalar<float>()();
    }
// --- summary_test.py ---
from tensorflow.python.framework import constant_op
from tensorflow.python.framework import dtypes
from tensorflow.python.framework import meta_graph
from tensorflow.python.framework import ops
...
        'family/outer/family/inner/audio/{}'.format(i) for i in range(3))
    self.assertEqual(tags, expected)

  @test_util.run_deprecated_v1
