// Vulnerable: VUL-CVE-2020-15203
prefix = "as_string_op",
    deps = STRING_DEPS,
)
// --- as_string_op.cc ---
                errors::InvalidArgument(
                    "Cannot select both scientific and shortest notation"));
    format_ = "%";
    if (width > -1) {
...
                    "Cannot select both scientific and shortest notation"));
    format_ = "%";
...
      strings::Appendf(&format_, "%s%d", fill_string.c_str(), width);
    }
    if (precision > -1) {
