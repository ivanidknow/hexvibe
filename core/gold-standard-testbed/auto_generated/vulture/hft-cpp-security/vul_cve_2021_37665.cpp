// Vulnerable: VUL-CVE-2021-37665
try {
      const Tensor& input = ctx->input(kInputTensorIndex);
      const Tensor& input_min_vec = ctx->input(kInputMinVecIndex);
      float* input_min_vec_data = (float*)const_cast<void*>(
...
      const Tensor& input = ctx->input(kInputTensorIndex);
      const Tensor& input_min_vec = ctx->input(kInputMinVecIndex);
      float* input_min_vec_data = (float*)const_cast<void*>(
          static_cast<const void*>(input_min_vec.flat<float>().data()));
...
      float* input_min_vec_data = (float*)const_cast<void*>(
...
      if (out_type_ == DT_QINT8) DCHECK(input_requested_min_float < 0.0f);

      const float factor = (out_type_ == DT_QINT8) ? 127.0f : 255.0f;
