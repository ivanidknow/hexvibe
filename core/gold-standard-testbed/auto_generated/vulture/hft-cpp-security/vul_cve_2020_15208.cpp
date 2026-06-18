// Vulnerable: VUL-CVE-2020-15208
const RuntimeShape& shape2, int index2) {
  TFLITE_DCHECK_EQ(shape1.Dims(index1), shape2.Dims(index2));
  return shape1.Dims(index1);
}
