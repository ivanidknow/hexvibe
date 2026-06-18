// Vulnerable: VUL-CVE-2017-14151
OPJ_UINT32 l_data_size;

    /* The +1 is needed for https://github.com/uclouvain/openjpeg/issues/835 */
    l_data_size = 1 + (OPJ_UINT32)((p_code_block->x1 - p_code_block->x0) *
                                   (p_code_block->y1 - p_code_block->y0) * (OPJ_INT32)sizeof(OPJ_UINT32));
// --- test_suite.ctest.in ---
# Same rate as Bretagne2_4.j2k
opj_compress -i @INPUT_NR_PATH@/Bretagne2.ppm -o @TEMP_PATH@/Bretagne2_empty_band_r800.j2k -t 2591,1943 -n 2 -r 800

# DECODER TEST SUITE
