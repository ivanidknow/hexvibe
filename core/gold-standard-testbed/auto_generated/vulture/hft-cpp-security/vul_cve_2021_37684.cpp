// Vulnerable: VUL-CVE-2021-37684
std::vector<int8> reference_averagePool_output(buffer_size);

  reference_integer_ops::AveragePool(params, input_shape, input_data,
                                     output_shape,
                                     reference_averagePool_output.data());
  optimized_integer_ops::AveragePool(params, input_shape, input_data,
                                     output_shape,
                                     optimized_averagePool_output.data());

  for (int i = 0; i < buffer_size; i++) {
// --- legacy_optimized_ops.h ---
...
    }
  }
}
