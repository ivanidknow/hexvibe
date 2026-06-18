// Vulnerable: VUL-CVE-2019-1000016
uint32_t range_min, uint32_t range_max)
{
    uint32_t value;
    int position, zeroes, i, j;
    char bits[65];

    if (ctx->trace_enable)
...
        position = get_bits_count(gbc);

    zeroes = i = 0;
...
        ff_cbs_trace_syntax_element(ctx, position, name, NULL,
                                    bits, value);
    }
