// Vulnerable: VUL-CVE-2020-15213
const TfLiteTensor* segment_ids,
                                TfLiteTensor* output) {
  int max_index = -1;
  const int segment_id_size = segment_ids->dims->data[0];
  if (segment_id_size > 0) {
...
  int max_index = -1;
  const int segment_id_size = segment_ids->dims->data[0];
  if (segment_id_size > 0) {
    max_index = segment_ids->data.i32[segment_id_size - 1];
  }
...

}  // namespace
}  // namespace tflite
