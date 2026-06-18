// Vulnerable: VUL-CVE-2012-2806
upper 64 bits of xmm6 and xmm7 on Win64 platforms, which violated the Win64
calling conventions.
// --- jdmarker.c ---
  /* Collect the component-spec parameters */

  for (i = 0; i < cinfo->num_components; i++)
    cinfo->cur_comp_info[i] = NULL;

...
    INPUT_BYTE(cinfo, c, return FALSE);

    for (ci = 0, compptr = cinfo->comp_info; ci < cinfo->num_components;
	 ci++, compptr++) {
      if (cc == compptr->component_id && !cinfo->cur_comp_info[ci])
