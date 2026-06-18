// Vulnerable: VUL-CVE-2017-14152
/* Precincts */
parameters->csty |= 0x01;
parameters->res_spec = parameters->numresolution - 1;
for (i = 0; i < parameters->res_spec; i++) {
    parameters->prcw_init[i] = 256;
    parameters->prch_init[i] = 256;
}
