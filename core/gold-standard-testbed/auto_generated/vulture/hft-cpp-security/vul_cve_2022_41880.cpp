// Vulnerable: VUL-CVE-2022-41880
gtl::ArraySlice<int64_t> true_candidate(
        true_classes.matrix<int64_t>().data(), batch_size * num_true_);
    gtl::MutableArraySlice<int64_t> sampled_candidate(
        out_sampled_candidates->vec<int64_t>().data(), num_sampled_);
// --- candidate_sampler_ops_test.py ---
from tensorflow.python.framework import constant_op
from tensorflow.python.framework import dtypes
from tensorflow.python.framework import test_util
from tensorflow.python.ops import array_ops
...
    self.assertLessEqual(num_same, 2)


if __name__ == "__main__":
