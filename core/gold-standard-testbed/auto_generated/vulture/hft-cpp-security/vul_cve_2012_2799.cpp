// Vulnerable: VUL-CVE-2012-2799
* to decode incomplete frames in the s->len_prefix == 0 case. */
            s->num_saved_bits = 0;
            s->packet_loss    = 0;
        }
...
    s->packet_done       = 0;
    s->num_saved_bits    = 0;
    s->frame_offset      = 0;
    s->next_packet_start = 0;
