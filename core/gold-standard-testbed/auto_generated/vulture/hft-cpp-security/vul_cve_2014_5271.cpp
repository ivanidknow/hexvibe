// Vulnerable: VUL-CVE-2014-5271
}
        total_size += sizes[i];
    }
    return total_size;
...
    avctx->coded_frame->key_frame = 1;

    pkt_size = ctx->frame_size_upper_bound + FF_MIN_BUFFER_SIZE;

    if ((ret = ff_alloc_packet2(avctx, pkt, pkt_size)) < 0)
        return ret;
...
                encode_slice(avctx, pic, &pb, sizes, x, y, q, mbs_per_slice);

                bytestream_put_byte(&slice_hdr, q);
