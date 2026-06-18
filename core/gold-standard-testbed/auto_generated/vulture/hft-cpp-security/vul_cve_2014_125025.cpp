// Vulnerable: VUL-CVE-2014-125025
pulse->pos[0]    = swb_offset[pulse_swb];
    pulse->pos[0]   += get_bits(gb, 5);
    if (pulse->pos[0] > 1023)
        return -1;
    pulse->amp[0]    = get_bits(gb, 4);
...
    for (i = 1; i < pulse->num_pulse; i++) {
        pulse->pos[i] = get_bits(gb, 5) + pulse->pos[i - 1];
        if (pulse->pos[i] > 1023)
            return -1;
        pulse->amp[i] = get_bits(gb, 4);
