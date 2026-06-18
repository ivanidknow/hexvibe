// Vulnerable: VUL-CVE-2015-3395
unsigned char stream_byte;
    unsigned int pixel_ptr = 0;
    int row_dec = pic->linesize[0];
    int row_ptr = (avctx->height - 1) * row_dec;
    int frame_size = row_dec * avctx->height;
    int i;

...
    int i;

    while (row_ptr >= 0) {
...
                    pic->data[0][row_ptr + pixel_ptr] = stream_byte & 0x0F;
                pixel_ptr++;
            }
