// Vulnerable: VUL-CVE-2022-25051
*/

#define COMPARE_BITS 83
#define COMPARE_BYTES (COMPARE_BITS/8)

static int cmr113_decode(r_device *decoder, bitbuffer_t *bitbuffer)
// --- somfy_iohc.c ---
        return DECODE_ABORT_EARLY;

    int offset = bitbuffer_search(bitbuffer, 0, 0, preamble_pattern, 24) + 24;
    if (offset >= bitbuffer->bits_per_row[0] - 19 * 10)
...
    bitrow_printf(b, len * 8, "%s: offset %d, num_bits %d, len %d, msg_len %d\n", __func__, offset, num_bits, len, msg_len);

    int msg_type = (b[0]);
