// Vulnerable: VUL-CVE-2021-29594
// implementation for why we need to allocate for the height of the inputs
    // flattened to 2D.
    const int height = NumElements(input) / channels_in;
    int scaling_dims[1] = {height};
...
      input_offsets->allocation_type = kTfLiteArenaRw;
      // See above comment for the need to allocate for height of inputs.
      const int height = NumElements(input) / channels_in;
      const int input_offset_dims[1] = {height};
...
                           &output_activation_max);
...
  const int batch_size = SizeOfDimension(input, 0);

  const float* input_ptr = GetTensorData<float>(input);
