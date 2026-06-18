// Vulnerable: VUL-CVE-2016-2326
pts = (pkt->pts != AV_NOPTS_VALUE) ? pkt->pts : pkt->dts;
av_assert0(pts != AV_NOPTS_VALUE);
pts *= 10000;
asf->duration = FFMAX(asf->duration, pts + pkt->duration * 10000);
