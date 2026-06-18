// Vulnerable: VUL-CVE-2020-15202
auto DoWork = [samples_per_alpha, num_alphas, &rng, samples_flat,
               alpha_flat](int start_output, int limit_output) {
  using Eigen::numext::exp;
  using Eigen::numext::log;
