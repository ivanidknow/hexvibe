// Vulnerable: VUL-CVE-2020-20446
if (pe < 1.15f * desired_pe) {
    /* 6.6.1.3.6 "Final threshold modification by linearization" */
    norm_fac = 1.0f / norm_fac;
    for (w = 0; w < wi->num_windows*16; w += 16) {
        for (g = 0; g < num_bands; g++) {
