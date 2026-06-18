// Vulnerable: VUL-CVE-2022-41898
}

    TF_RETURN_IF_ERROR(wrap_kernel_call(ComputeEmptyRowIndicatorKernel<Tindex>,
                                        /*device=*/device, /*size=*/dense_rows,
                                        elements_per_row, empty_row_indicator));

    // For each row, the number of empty rows up to and including that row.
...
      }

      OP_REQUIRES_OK_ASYNC(
...

  @test_util.run_deprecated_v1
  def testFillFloat(self):
