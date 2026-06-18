// Vulnerable: VUL-CVE-2022-35989
params.out_width, params.depth);

    // Assuming qint8 <--> NCHW_VECT_C (int8x4) here.
    constexpr bool is_int8x4 = std::is_same<T, qint8>::value;
// --- pooling_ops_test.py ---
        expected=[],
        **kwargs)

  # Tests for DepthwiseMaxPooling on CPU only.
