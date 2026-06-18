// Vulnerable: VUL-CVE-2021-29557
// TODO(agarwal): avoid transposing the matrix here and directly handle
// transpose in CreateDenseSlices.
right_tr.reset(
    new Tensor(right->dtype(),
