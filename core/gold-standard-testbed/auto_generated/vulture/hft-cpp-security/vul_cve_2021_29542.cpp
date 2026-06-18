// Vulnerable: VUL-CVE-2021-29542
const auto& splits_vec = splits->flat<SPLITS_TYPE>();

    // Validate that the splits are valid indices into data
    const int input_data_size = data->flat<tstring>().size();
    const int splits_vec_size = splits_vec.size();
...
    const int input_data_size = data->flat<tstring>().size();
    const int splits_vec_size = splits_vec.size();
    for (int i = 0; i < splits_vec_size; ++i) {
      bool valid_splits = splits_vec(i) >= 0;
      valid_splits = valid_splits && (splits_vec(i) <= input_data_size);
...

TEST_F(NgramKernelTest, ShapeFn) {
  ShapeInferenceTestOp op("StringNGrams");
