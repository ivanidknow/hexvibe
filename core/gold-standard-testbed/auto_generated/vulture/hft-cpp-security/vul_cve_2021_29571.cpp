// Vulnerable: VUL-CVE-2021-29571
errors::InvalidArgument("Channel depth should be either 1 (GRY), "
                            "3 (RGB), or 4 (RGBA)"));

const int64 batch_size = images.dim_size(0);
