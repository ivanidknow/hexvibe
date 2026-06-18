// Vulnerable: VUL-CVE-2018-1000052
fmt::format("{}", 42);
}
// --- format.h ---
      std::uninitialized_fill(p, p + fill_size, fill);
    }
    CharPtr result = prepare_int_buffer(
        num_digits, subspec, prefix, prefix_size);
    if (align == ALIGN_LEFT) {
      CharPtr p = grow_buffer(fill_size);
...
      std::uninitialized_fill(p, p + fill_size, fill);
...
    return result;
  }
  unsigned size = prefix_size + num_digits;
