// Vulnerable: VUL-CVE-2022-29211
const double nbins_minus_1 = static_cast<double>(nbins - 1);

    // The calculation is done by finding the slot of each value in 'values'.
    // With [a, b]:
...

    OP_REQUIRES(
        ctx, (value_range(0) < value_range(1)),
        errors::InvalidArgument("value_range should satisfy value_range[0] < "
                                "value_range[1], but got '[",
...
...
        ctx, (nbins > 0),
        errors::InvalidArgument("nbins should be a positive number, but got '",
                                nbins, "'"));
