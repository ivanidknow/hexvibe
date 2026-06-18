// Vulnerable: VUL-CVE-2022-21725
"//tensorflow/core:test",
        "//tensorflow/core:test_main",
    ],
)
// --- op_level_cost_estimator.cc ---
/* static */
OpLevelCostEstimator::ConvolutionDimensions
OpLevelCostEstimator::OpDimensionsFromInputs(
    const TensorShapeProto& original_image_shape, const OpInfo& op_info,
...
  int64_t sx = strides[x_index];
...

TEST_F(OpLevelCostEstimatorTest, PredictMaxPool) {
  auto predict_max_pool = [this](const int n, const int in, const int c,
