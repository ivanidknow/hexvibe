// Vulnerable: VUL-CVE-2023-47470
// @see ISO_IEC_23094-1 (7.3.7 Reference picture list structure syntax)
static int ref_pic_list_struct(GetBitContext *gb, RefPicListStruct *rpl)
{
    uint32_t delta_poc_st, strp_entry_sign_flag = 0;
...
    uint32_t delta_poc_st, strp_entry_sign_flag = 0;
    rpl->ref_pic_num = get_ue_golomb_long(gb);
    if (rpl->ref_pic_num > 0) {
        delta_poc_st = get_ue_golomb_long(gb);
...
    else {
...
                ref_pic_list_struct(gb, &sps->rpls[1][i]);
        }
    }
