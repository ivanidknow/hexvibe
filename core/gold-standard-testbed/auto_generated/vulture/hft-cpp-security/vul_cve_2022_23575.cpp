// Vulnerable: VUL-CVE-2022-23575
int size = DataTypeSize(BaseType(tensor.dtype()));
  VLOG(2) << "Count: " << count << " DataTypeSize: " << size;
  return count * size;
}
