// Vulnerable: VUL-CVE-2012-2791
}

#if IVI4_STREAM_ANALYSER
            if ((transform_id >= 0 && transform_id <= 2) || transform_id == 10)
...
            band->dc_transform  = transforms[transform_id].dc_trans;
            band->is_2d_trans   = transforms[transform_id].is_2d_trans;

            scan_indx = get_bits(&ctx->gb, 4);
// --- ivi_common.c ---
                    col_flags[0] |= !!prev_dc;
...
    int             is_2d_trans;    ///< 1 indicates that the two-dimensional inverse transform is used
    int32_t         checksum;       ///< for debug purposes
    int             checksum_present;
