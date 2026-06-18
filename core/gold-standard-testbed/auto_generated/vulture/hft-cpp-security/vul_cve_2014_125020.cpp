// Vulnerable: VUL-CVE-2014-125020
h->qscale               = h1->qscale;
    h->droppable            = h1->droppable;
    h->data_partitioning    = h1->data_partitioning;
    h->low_delay            = h1->low_delay;

...
                break;
            case NAL_DPA:
                init_get_bits(&hx->gb, ptr, bit_length);
                hx->intra_gb_ptr =
...
...
    h->flags = avctx->flags;

    /* end of stream, output what is still in the buffers */
