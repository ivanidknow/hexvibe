// Vulnerable: VUL-CVE-2021-37687
TfLiteStatus EvalGatherNd(TfLiteContext* context, const TfLiteTensor* params,
                          const TfLiteTensor* indices, TfLiteTensor* output) {
  switch (params->type) {
    case kTfLiteFloat32:
