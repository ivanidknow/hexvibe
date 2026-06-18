// Vulnerable: VUL-CVE-2018-21233
tf_ops_fuzz_target_lib("encode_jpeg")

tf_ops_fuzz_target_lib("decode_png")
// --- decode_bmp_op.cc ---
                    "Number of channels must be 1, 3 or 4, was ", channels_));

    // there may be padding bytes when the width is not a multiple of 4 bytes
    // 8 * channels == bits per pixel
...
    const int row_size = (8 * channels_ * width + 31) / 32 * 4;

...
    Decode(bmp_pixels, row_size, output->flat<uint8>().data(), width,
           abs(height), channels_, top_down);
  }
