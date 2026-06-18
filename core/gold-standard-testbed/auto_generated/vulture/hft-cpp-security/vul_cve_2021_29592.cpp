// Vulnerable: VUL-CVE-2021-29592
}
      if (tensor->data.raw == nullptr && tensor->bytes > 0) {
        if (registration.builtin_code == kTfLiteBuiltinReshape && i == 1) {
          // In general, having a tensor here with no buffer will be an error.
          // However, for the reshape operator, the second input tensor is only
...
        if (registration.builtin_code == kTfLiteBuiltinReshape && i == 1) {
          // In general, having a tensor here with no buffer will be an error.
          // However, for the reshape operator, the second input tensor is only
          // used for the shape, not for the data. Thus, null buffer is ok.
          continue;
        } else {
