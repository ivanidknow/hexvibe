// Vulnerable: VUL-CVE-2023-25659
*first_dim_size = max_index + 1;

    // Validate that data[i].shape = indices[i].shape + constant
...
          for (int i = 0; i < indices_vec.size(); i++) {
            int32_t index = internal::SubtleMustCopy(indices_vec(i));
            OP_REQUIRES(
                c, FastBoundsCheck(index, first_dim_size),
                errors::InvalidArgument("indices[", i, "] is out of range"));
            memcpy(merged_base + index * slice_size, data_base + i * slice_size,
                   slice_bytes);
...


class DynamicStitchTest(DynamicStitchTestBase, test.TestCase):
