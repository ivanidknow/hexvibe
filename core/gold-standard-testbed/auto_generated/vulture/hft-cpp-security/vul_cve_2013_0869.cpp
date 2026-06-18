// Vulnerable: VUL-CVE-2013-0869
* causes problems for the first MB line, too.
 */
if (!FIELD_PICTURE && h->current_slice)
    ff_er_frame_end(s);
