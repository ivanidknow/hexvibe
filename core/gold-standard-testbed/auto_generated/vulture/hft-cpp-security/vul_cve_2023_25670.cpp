// Vulnerable: VUL-CVE-2023-25670
// "min_freezed_output" and "max_freezed_output" are the requested range
      // for the output.
      min_output_value = context->input(7).flat<float>()(0);
      max_output_value = context->input(8).flat<float>()(0);
    } else {
      ComputeOutputRangeForInt32(context, &min_output_value, &max_output_value);
...
                                  float* min_output_value,
                                  float* max_output_value) {
    const float min_input = context->input(3).flat<float>()(0);
    const float max_input = context->input(4).flat<float>()(0);
...
}  // namespace tensorflow

#endif  // INTEL_MKL && ENABLE_MKL
