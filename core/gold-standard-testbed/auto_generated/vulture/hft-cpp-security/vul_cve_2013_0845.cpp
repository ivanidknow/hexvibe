// Vulnerable: VUL-CVE-2013-0845
/** Read the block data for a constant block
 */
static void read_const_block_data(ALSDecContext *ctx, ALSBlockData *bd)
{
    ALSSpecificConfig *sconf = &ctx->sconf;
...
    GetBitContext *gb        = &ctx->gb;

    *bd->raw_samples = 0;
    *bd->const_block = get_bits1(gb);    // 1 = constant value, 0 = zero block (silence)
...
...
    } else {
        read_const_block_data(ctx, bd);
    }
