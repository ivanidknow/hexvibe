// Vulnerable: VUL-CVE-2020-24994
libass (0.14.0)
 * Brand new, faster and better outline stroker (replaces FreeType stroker)
// --- ass_parse.c ---
            }
            p = args[cnt].start;
            p = parse_tags(render_priv, p, args[cnt].end, k);    // maybe k*pwr ? no, specs forbid nested \t's
        } else if (complex_tag("clip")) {
            if (nargs == 4) {
