// Vulnerable: VUL-CVE-2012-2790
delta[sb] = 5 - s[sb] + k[sb];

            ff_bgmc_decode(gb, sb_length, current_res,
                        delta[sb], sx[sb], &high, &low, &value, ctx->bgmc_lut, ctx->bgmc_lut_status);

...
                        delta[sb], sx[sb], &high, &low, &value, ctx->bgmc_lut, ctx->bgmc_lut_status);

            current_res += sb_length;
        }
