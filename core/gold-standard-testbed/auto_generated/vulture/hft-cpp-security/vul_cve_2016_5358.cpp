// Vulnerable: VUL-CVE-2016-5358
int offset = 0;
	guint32 pkt_len, rectype, dlt;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PKTAP");
...
	if (rectype == PKT_REC_PACKET) {
		next_tvb = tvb_new_subset_remaining(tvb, pkt_len);
		dissector_try_uint(wtap_encap_dissector_table,
		    wtap_pcap_encap_to_wtap_encap(dlt), next_tvb, pinfo, tree);
	}
}
...
    dissector_try_uint(wtap_encap_dissector_table, linktype, new_tvb, pinfo, top_tree);

    if (!info_added) {
