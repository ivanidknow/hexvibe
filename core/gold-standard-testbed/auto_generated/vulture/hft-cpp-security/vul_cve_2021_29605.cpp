// Vulnerable: VUL-CVE-2021-29605
TfLiteIntArray* TfLiteIntArrayCreate(int size) {
  TfLiteIntArray* ret =
      (TfLiteIntArray*)malloc(TfLiteIntArrayGetSizeInBytes(size));
  ret->size = size;
  return ret;
// --- embedding_lookup_sparse.cc ---
  // Resize output tensor.
  TfLiteIntArray* output_shape = TfLiteIntArrayCreate(output_rank);
  int k = 0;
  int embedding_size = 1;
