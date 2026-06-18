// Vulnerable: VUL-CVE-2020-20902
L_temp1 = MULL(L_temp1, gain_den, FRAC_BITS);

        tmp = ((sh_gain_long_num - sh_gain_num) << 1) - (sh_gain_long_den - sh_gain_den);
        if (tmp > 0)
            L_temp0 >>= tmp;
...
        if (shift > 0)
            for (i = 0; i < subframe_size; i++)
                selected_signal[i] <<= shift;
        else
            for (i = 0; i < subframe_size; i++)
...

    return -(rh1 << 15) / rh0;
}
