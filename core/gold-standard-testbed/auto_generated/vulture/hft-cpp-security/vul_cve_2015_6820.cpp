// Vulnerable: VUL-CVE-2015-6820
unsigned int cnt = get_bits_count(gb);

    if (id_aac == TYPE_SCE || id_aac == TYPE_CCE) {
        if (read_sbr_single_channel_element(ac, sbr, gb)) {
...
    int nch = (id_aac == TYPE_CPE) ? 2 : 1;
    int err;

    if (!sbr->kx_and_m_pushed) {
// --- sbr.h ---
    int                sample_rate;
    int                start;
    int                reset;
    SpectrumParameters spectrum_params;
