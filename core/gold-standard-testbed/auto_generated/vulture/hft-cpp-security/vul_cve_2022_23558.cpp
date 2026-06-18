// Vulnerable: VUL-CVE-2022-23558
#endif  // TF_LITE_STATIC_MEMORY

int TfLiteIntArrayGetSizeInBytes(int size) {
  static TfLiteIntArray dummy;

...
  static TfLiteIntArray dummy;

  int computed_size = sizeof(dummy) + sizeof(dummy.data[0]) * size;
#if defined(_MSC_VER)
  // Context for why this is needed is in http://b/189926408#comment21
...
int TfLiteIntArrayGetSizeInBytes(int size);

#ifndef TF_LITE_STATIC_MEMORY
