// Vulnerable: VUL-CVE-2016-7163
/* memory allocation for include */
l_current_pi->include = (OPJ_INT16*) opj_calloc((l_tcp->numlayers +1) * l_step_l, sizeof(OPJ_INT16));
if
	(!l_current_pi->include)
