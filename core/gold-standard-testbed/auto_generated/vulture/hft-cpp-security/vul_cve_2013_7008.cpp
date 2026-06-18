// Vulnerable: VUL-CVE-2013-7008
/* Mark old field/frame as completed */
            if (!last_pic_droppable && h0->cur_pic_ptr->tf.owner == h0->avctx) {
                ff_thread_report_progress(&h0->cur_pic_ptr->tf, INT_MAX,
                                          last_pic_structure == PICT_BOTTOM_FIELD);
...
                /* Previous field is unmatched. Don't display it, but let it
                 * remain for reference if marked as such. */
                if (!last_pic_droppable && last_pic_structure != PICT_FRAME) {
                    ff_thread_report_progress(&h0->cur_pic_ptr->tf, INT_MAX,
                                              last_pic_structure == PICT_TOP_FIELD);
...
...
                    if (!last_pic_droppable && last_pic_structure != PICT_FRAME) {
                        ff_thread_report_progress(&h0->cur_pic_ptr->tf, INT_MAX,
                                                  last_pic_structure == PICT_TOP_FIELD);
