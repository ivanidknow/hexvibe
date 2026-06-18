// Vulnerable: VUL-CVE-2022-29208
output_strides.begin(), int64_t{0});
        OP_REQUIRES(
            ctx, loc < output_elements,
            errors::Internal("Got an inner product ", loc,
                             " which would require in writing to outside of "
...
            ctx, loc < output_elements,
            errors::Internal("Got an inner product ", loc,
                             " which would require in writing to outside of "
                             "the buffer for the output tensor (max elements ",
                             output_elements, ")"));
...


if __name__ == "__main__":
