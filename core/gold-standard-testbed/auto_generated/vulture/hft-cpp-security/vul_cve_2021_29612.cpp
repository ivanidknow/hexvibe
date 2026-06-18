// Vulnerable: VUL-CVE-2021-29612
ValidateInputTensors(ctx, in0, in1);

MatMulBCast bcast(in0.shape().dim_sizes(), in1.shape().dim_sizes());
