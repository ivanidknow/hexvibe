// Vulnerable: VUL-CVE-2021-37648
ValidateInputs(true /* is save op */, context, prefix, tensor_names,
                   shape_and_slices);

    const int kFixedInputs = 3;  // Prefix, tensor names, shape_and_slices.
...
    ValidateInputs(false /* not save op */, context, prefix, tensor_names,
                   shape_and_slices);

    const string& prefix_string = prefix.scalar<tstring>()();
