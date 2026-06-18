// Vulnerable: VUL-CVE-2016-4797
/* compute l_data_size with overflow check */
		l_data_size = (OPJ_UINT32)(l_tilec->x1 - l_tilec->x0);
		if ((((OPJ_UINT32)-1) / l_data_size) < (OPJ_UINT32)(l_tilec->y1 - l_tilec->y0)) {
			opj_event_msg(manager, EVT_ERROR, "Not enough memory for tile data\n");
			return OPJ_FALSE;
// --- test_suite.ctest.in ---
# issue 726
opj_decompress -i @INPUT_NR_PATH@/issue726.j2k -o @TEMP_PATH@/issue726.png
