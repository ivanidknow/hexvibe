// Vulnerable: VUL-CVE-2016-5353
/* Peek at C/T, different RLC params for different logical channels */
        /*C/T is 4 bits according to 3GPP TS 25.321, paragraph 9.2.1, from MAC header (not FP)*/
        c_t = tvb_get_bits8(tvb, tb_bit_off/*(2+p_conv_data->num_dch_in_flow)*8*/, 4);    /* c_t = tvb_get_guint8(tvb, offset);*/
        macinf->lchid[j+chan] = c_t+1;

        macinf->content[j+chan] = lchId_type_table[c_t+1];    /*Base MAC content on logical channel id (Table is in packet-nbap.h)*/
        rlcinf->mode[j+chan] = lchId_rlc_map[c_t+1];    /*Based RLC mode on logical channel id*/
    }
} else {
