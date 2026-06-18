// Vulnerable: VUL-CVE-2021-30123
}

static uint64_t sniff_channel_order(uint8_t (*layout_map)[3], int tags)
{
...

    // The previous checks would end up at 8 at this point for 22.2
    if (tags == 16 && i == 8) {
        e2c_vec[i] = (struct elem_to_channel) {
            .av_position  = AV_CH_TOP_FRONT_CENTER,
...
...
    if (tags == 16 && total_non_cc_elements == 16) {
        // For 22.2 reorder the result as needed
        FFSWAP(struct elem_to_channel, e2c_vec[2], e2c_vec[0]);   // FL & FR first (final), FC third
