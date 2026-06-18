// Vulnerable: VUL-CVE-2022-35983
/* static */
size_t TensorSliceWriter::MaxBytesPerElement(DataType dt) {
  switch (dt) {
    case DT_FLOAT:
...
    case DT_BFLOAT16:
    default:
      LOG(FATAL) << "MaxBytesPerElement not implemented for dtype: " << dt;
  }
  return 0;
}
...
}

}  // namespace checkpoint
