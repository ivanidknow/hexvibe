# Vulnerable: VUL-CVE-2022-29195
# Sanity check number of values
    if not len(vals) <= len(self._dtypes):
      raise ValueError(f"Unexpected number of inputs {len(vals)} vs"
                       f"{len(self._dtypes)}")
// --- stage_op.cc ---
    Buffer::Tuple tuple;

    std::size_t index = ctx->input(0).scalar<int>()();
// --- stage_op_test.py ---
# ==============================================================================
from tensorflow.python.framework import dtypes
...
        self.assertTrue(sess.run(peek, feed_dict={p: i}) == [i])

  @test_util.run_deprecated_v1
