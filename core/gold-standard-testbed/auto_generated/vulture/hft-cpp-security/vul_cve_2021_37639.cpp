// Vulnerable: VUL-CVE-2021-37639
errors::InvalidArgument(
            "Input 0 (file_pattern) must be a string scalar; got a tensor of ",
            size, "elements"));
  }
  const string& file_pattern = file_pattern_t.flat<tstring>()(0);
...

  const Tensor& tensor_name_t = context->input(1);
  const string& tensor_name = tensor_name_t.flat<tstring>()(restore_index);
