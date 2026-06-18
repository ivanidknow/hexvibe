// Vulnerable: VUL-CVE-2020-22041
}

static const AVFilterPad random_inputs[] = {
    {
...
    .priv_class  = &random_class,
    .init        = init,
    .inputs      = random_inputs,
    .outputs     = random_outputs,
