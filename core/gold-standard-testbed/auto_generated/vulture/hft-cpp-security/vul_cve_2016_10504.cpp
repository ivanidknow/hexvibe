// Vulnerable: VUL-CVE-2016-10504
OPJ_UINT32 l_data_size;

l_data_size = (OPJ_UINT32)((p_code_block->x1 - p_code_block->x0) *
                           (p_code_block->y1 - p_code_block->y0) * (OPJ_INT32)sizeof(OPJ_UINT32));

if (l_data_size > p_code_block->data_size) {
