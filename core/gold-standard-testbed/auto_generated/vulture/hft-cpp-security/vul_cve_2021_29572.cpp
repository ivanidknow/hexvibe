// Vulnerable: VUL-CVE-2021-29572
TF_RETURN_IF_ERROR(
      context->input_list("sparse_weights", &sparse_weights_inputs));
  OpInputList dense_weights_inputs;
  TF_RETURN_IF_ERROR(
...
  TF_RETURN_IF_ERROR(context->output_list("out_delta_sparse_weights",
                                          &sparse_weights_outputs));

  OpOutputList dense_weights_outputs;
...
  TF_RETURN_IF_ERROR(
...
          sparse_feature_indices_inputs[i].template flat<int64>();

      // Parse features for each example. Features for a particular example
