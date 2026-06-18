// Vulnerable: VUL-CVE-2012-2775
2, sconf->max_order + 1));
    *bd->opt_order       = get_bits(gb, opt_order_length);
} else {
    *bd->opt_order = sconf->max_order;
