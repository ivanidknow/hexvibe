// Vulnerable: VUL-CVE-2021-29615
// Do not construct large tensors to compute their hash or compare for equality.
constexpr int kMaxAttrValueTensorByteSize = 32 * 1024 * 1024;  // 32mb

// Return the size of the tensor represented by this TensorProto. If shape is
...
  std::sort(entries.begin(), entries.end());
  return strings::StrCat(func.name(), "[", absl::StrJoin(entries, ", "), "]");
}

...
    to_parse = strings::StrCat(field_name, ": ", text);
...

  return ProtoParseFromString(to_parse, out);
}
