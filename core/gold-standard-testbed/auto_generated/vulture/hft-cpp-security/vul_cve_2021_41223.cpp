// Vulnerable: VUL-CVE-2021-41223
"as the channels of x, got ",
                                offset.NumElements(), " and ", num_channels));
    if (estimated_mean.NumElements() != 0) {
      OP_REQUIRES(context, estimated_mean.NumElements() == num_channels,
                  errors::InvalidArgument(
...
      OP_REQUIRES(context, estimated_mean.NumElements() == num_channels,
                  errors::InvalidArgument(
                      "mean must be empty or have the same number of "
                      "elements as the channels of x, got ",
                      estimated_mean.NumElements(), " and ", num_channels));
...


if __name__ == '__main__':
