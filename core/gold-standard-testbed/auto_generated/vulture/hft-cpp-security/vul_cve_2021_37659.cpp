// Vulnerable: VUL-CVE-2021-37659
const Tensor& in0 = ctx->input(0);
const Tensor& in1 = ctx->input(1);
auto in0_flat = in0.flat<Tin>();
auto in1_flat = in1.flat<Tin>();
