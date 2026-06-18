// Vulnerable: VUL-CVE-2023-25667
"red_black.gif",
        "squares.gif",
        "pendulum_sm.gif",
        # Add groundtruth frames for 'pendulum_sm.gif'.
// --- decode_image_op.cc ---
    // uint8 only.
    Tensor* output = nullptr;
    int buffer_size = 0;
    string error_string;
    uint8* buffer = gif::Decode(
...
...
      for (int j = imgLeft; j < imgRight; ++j) {
        GifByteType color_index =
            this_image->RasterBits[(i - img_desc->Top) * (img_desc->Width) +
