# Vulnerable: VUL-CVE-2020-15190
self.evaluate(result)

  @test_util.run_deprecated_v1
  def testQIntArgAndRet(self):
// --- kernel_and_device.cc ---
    outputs->clear();
    for (int i = 0; i < context.num_outputs(); ++i) {
      outputs->push_back(Tensor(*context.mutable_output(i)));
    }
  }
