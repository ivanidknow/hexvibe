// Vulnerable: VUL-CVE-2018-20847
/* here calculation of tx0, tx1, ty0, ty1, maxprec, l_dx and l_dy */
	*p_tx0 = opj_int_max((OPJ_INT32)(p_cp->tx0 + p * p_cp->tdx), (OPJ_INT32)p_image->x0);
	*p_tx1 = opj_int_min((OPJ_INT32)(p_cp->tx0 + (p + 1) * p_cp->tdx), (OPJ_INT32)p_image->x1);
	*p_ty0 = opj_int_max((OPJ_INT32)(p_cp->ty0 + q * p_cp->tdy), (OPJ_INT32)p_image->y0);
	*p_ty1 = opj_int_min((OPJ_INT32)(p_cp->ty0 + (q + 1) * p_cp->tdy), (OPJ_INT32)p_image->y1);

	/* max precision and resolution is 0 (can only grow)*/
// --- tcd.c ---
	/* 4 borders of the tile rescale on the image if necessary */
	l_tile->x0 = opj_int_max((OPJ_INT32)(l_cp->tx0 + p * l_cp->tdx), (OPJ_INT32)l_image->x0);
	l_tile->y0 = opj_int_max((OPJ_INT32)(l_cp->ty0 + q * l_cp->tdy), (OPJ_INT32)l_image->y0);
...
	l_tile->y1 = opj_int_min((OPJ_INT32)(l_cp->ty0 + (q + 1) * l_cp->tdy), (OPJ_INT32)l_image->y1);
	/* testcase 1888.pdf.asan.35.988 */
	if (l_tccp->numresolutions == 0) {
