// Vulnerable: VUL-CVE-2013-0894
return AVERROR_INVALIDDATA;
}
floor_setup->data.t0.amplitude_offset = get_bits(gb, 8);
floor_setup->data.t0.num_books        = get_bits(gb, 4) + 1;
