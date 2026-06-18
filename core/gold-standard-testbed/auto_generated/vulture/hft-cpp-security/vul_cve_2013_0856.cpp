// Vulnerable: VUL-CVE-2013-0856
/* read warm-up samples */
for (i = 1; i <= lpc_order; i++)
    buffer_out[i] = sign_extend(buffer_out[i - 1] + error_buffer[i], bps);
