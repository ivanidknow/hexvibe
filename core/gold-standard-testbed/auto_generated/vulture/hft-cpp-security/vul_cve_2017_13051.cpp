// Vulnerable: VUL-CVE-2017-13051
rsvp_fast_reroute-oobr	rsvp_fast_reroute-oobr.pcap	rsvp_fast_reroute-oobr.out -v -c1
esis_opt_prot-oobr	esis_opt_prot-oobr.pcap		esis_opt_prot-oobr.out	-v -c1

# bad packets from Katie Holly
// --- print-rsvp.c ---
		total_subobj_len = obj_tlen;
                while(total_subobj_len > 0) {
                    subobj_len  = EXTRACT_16BITS(obj_tptr);
                    subobj_type = (EXTRACT_16BITS(obj_tptr+2))>>8;
...
                           subobj_len));

                    if(subobj_len == 0)
                        goto invalid;
