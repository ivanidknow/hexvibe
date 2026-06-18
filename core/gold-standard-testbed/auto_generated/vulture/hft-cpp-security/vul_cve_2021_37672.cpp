// Vulnerable: VUL-CVE-2021-37672
TF_RETURN_IF_ERROR(context->input("example_labels", &example_labels_t));
auto example_labels = example_labels_t->flat<float>();

OpInputList dense_features_inputs;
