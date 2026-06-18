// Vulnerable: VUL-CVE-2022-29213
auto fft_length_as_vec = fft_length.vec<int32>();
      for (int i = 0; i < fft_rank; ++i) {
        fft_shape[i] = fft_length_as_vec(i);
        // Each input dimension must have length of at least fft_shape[i]. For
// --- fft_ops_test.py ---
        rtol=tol, atol=tol)


@test_util.run_all_in_graph_and_eager_modes
