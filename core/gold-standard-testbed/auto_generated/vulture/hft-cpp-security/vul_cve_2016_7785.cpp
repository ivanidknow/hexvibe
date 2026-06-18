// Vulnerable: VUL-CVE-2016-7785
//        av_assert1(st2->codecpar->block_align);
        av_assert0(fabs(av_q2d(st2->time_base) - ast2->scale / (double)ast2->rate) < av_q2d(st2->time_base) * 0.00000001);
        index = av_index_search_timestamp(st2,
                                          av_rescale_q(timestamp,
