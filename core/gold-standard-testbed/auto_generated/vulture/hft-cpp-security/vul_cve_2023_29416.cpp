// Vulnerable: VUL-CVE-2023-29416
#define KiB(x) ((x)*1024)
#define MiB(x) ((x)*1024 * 1024)

#include <inttypes.h>
// --- libbz3.c ---
    bz3_state->swap_buffer = malloc(bz3_bound(block_size));
    bz3_state->sais_array = malloc((block_size + 128) * sizeof(s32));
    memset(bz3_state->sais_array, 0, sizeof(s32) * (block_size + 128));

    bz3_state->lzp_lut = calloc(1 << LZP_DICTIONARY, sizeof(s32));
...
...
    // Undo BWT
    if (libsais_unbwt(b1, b2, state->sais_array, size_src, NULL, bwt_idx) < 0) {
        state->last_error = BZ3_ERR_BWT;
