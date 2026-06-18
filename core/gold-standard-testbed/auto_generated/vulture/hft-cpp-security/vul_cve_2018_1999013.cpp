// Vulnerable: VUL-CVE-2018-1999013
size2 = avio_rb32(pb);
ret = ff_rm_read_mdpr_codecdata(s, s->pb, st2, st2->priv_data,
                                size2, mime);
if (ret < 0)
    return ret;
