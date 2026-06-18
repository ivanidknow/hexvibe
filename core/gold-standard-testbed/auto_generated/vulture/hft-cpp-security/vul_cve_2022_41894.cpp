// Vulnerable: VUL-CVE-2022-41894
const int outer_size =
        batches * output_depth * output_height * output_width;
    const int num_channels = input_shape.Dims(4);
    for (int n = 0; n < outer_size; ++n) {
      for (int c = 0; c < output_num_channels; ++c) {
...
                                                   float_activation_max);
      }
      data_ptr += num_channels;
    }
  } else {
