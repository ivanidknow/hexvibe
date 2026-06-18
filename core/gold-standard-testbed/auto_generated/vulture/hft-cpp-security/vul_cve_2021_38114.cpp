// Vulnerable: VUL-CVE-2021-38114
static int dnxhd_init_vlc(DNXHDContext *ctx, uint32_t cid, int bitdepth)
{
    if (cid != ctx->cid) {
        const CIDEntry *cid_table = ff_dnxhd_get_cid_table(cid);
...
        ff_free_vlc(&ctx->run_vlc);

        init_vlc(&ctx->ac_vlc, DNXHD_VLC_BITS, 257,
                 ctx->cid_table->ac_bits, 1, 1,
                 ctx->cid_table->ac_codes, 2, 2, 0);
...
...
    }
    return 0;
}
