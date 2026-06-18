// Vulnerable: VUL-CVE-2023-40032
20/7/23 8.14.3
// --- svgload.c ---
 *
 *   - case-insensitive
 *   - needle must be zero-terminated, but hackstack need not be
 *   - haystack can be null-terminated
 *   - if haystack is shorter than len bytes, that'll end the search
...
                                return( NULL );

                        /* End of haystack. There can't be a complete needle
...
					haystack_start + len_bytes );
                        needle_char =
				g_utf8_find_next_char( needle_char, NULL );
