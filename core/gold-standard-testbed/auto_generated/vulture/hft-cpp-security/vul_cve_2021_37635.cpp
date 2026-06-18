// Vulnerable: VUL-CVE-2021-37635
for (const auto &g : sp.group(reduction.group_by_dims)) {
      Op::template Run<T>(ctx, reduced_val, g.template values<T>());
      const int64_t idx = CoordinatesToFlatIndex(g.group(), output_strides);
      out_flat(idx) = reduced_val();
...
      Op::template Run<T>(ctx, reduced_val, g.template values<T>());
      const int64_t idx = CoordinatesToFlatIndex(g.group(), output_strides);
      out_flat(idx) = reduced_val();
      VLOG(2) << "coords: " << absl::StrJoin(g.group(), ",")
