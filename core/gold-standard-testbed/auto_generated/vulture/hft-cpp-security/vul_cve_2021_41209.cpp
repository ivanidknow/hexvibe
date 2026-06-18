// Vulnerable: VUL-CVE-2021-41209
void Compute(OpKernelContext* ctx) override {
    auto value = ctx->input(0);
    auto update = ctx->input(1);
// --- stack_op_test.py ---
import numpy as np

from tensorflow.python.eager import context
from tensorflow.python.framework import constant_op
...

from tensorflow.python.eager import context
...
            self.assertAllEqual(c, data)

  def testSimpleParallelGPU(self):
