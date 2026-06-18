// Vulnerable: VUL-CVE-2022-29212
}

template <typename input_dtype, reference_ops::ComparisonFn<int32> opname>
void ComparisonQuantized(const TfLiteTensor* input1, const TfLiteTensor* input2,
...

    int32 input1_multiplier;
    int input1_shift;
    QuantizeMultiplierSmallerThanOneExp(input1->params.scale,
...
    int32 input1_multiplier;
...

TEST(ComparisonsTest, QuantizedUInt8GreaterEqualWithBroadcast) {
  const float kMin = -1.f;
