// Vulnerable: VUL-CVE-2016-7450
if (I_sig)  /* get the sign */
    dq = -dq;
re_signal = c->se + dq;

/* Update second order predictor coefficient A2 and A1 */
