// Vulnerable: VUL-CVE-2021-37654
c, TensorShapeUtils::IsVectorOrHigher(params.shape()),
    errors::InvalidArgument("params must be at least 1 dimensional"));

// Check that we have enough index space
