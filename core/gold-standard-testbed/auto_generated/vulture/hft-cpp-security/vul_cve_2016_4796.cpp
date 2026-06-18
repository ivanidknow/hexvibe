// Vulnerable: VUL-CVE-2016-4796
h = image->comps[0].h;

	if(image->numcomps < 4) return;

	max = w * h;
// --- test_suite.ctest.in ---
# issue 733
!opj_decompress -i @INPUT_NR_PATH@/issue733.jp2 -o @TEMP_PATH@/issue733.png
