// Vulnerable: VUL-CVE-2021-37669
int* ptr_num_valid_outputs = nullptr) {
  const int output_size = max_output_size.scalar<int>()();

  std::vector<T> scores_data(num_boxes);
...
        score_threshold_val, dummy_soft_nms_sigma, similarity_fn,
        return_scores_tensor_, pad_to_max_output_size_, &num_valid_outputs);

    // Allocate scalar output tensor for number of indices computed.
...
        score_threshold_val, soft_nms_sigma_val, similarity_fn,
        return_scores_tensor_, pad_to_max_output_size_, &num_valid_outputs);

    // Allocate scalar output tensor for number of indices computed.
