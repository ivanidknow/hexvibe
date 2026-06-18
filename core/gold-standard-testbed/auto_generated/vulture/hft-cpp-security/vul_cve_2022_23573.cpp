// Vulnerable: VUL-CVE-2022-23573
// We always return the input ref.
context->forward_ref_input_to_ref_output(0, 0);

// We can't always know how this value will be used downstream, so make
