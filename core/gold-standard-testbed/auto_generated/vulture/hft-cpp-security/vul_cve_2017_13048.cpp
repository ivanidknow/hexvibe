// Vulnerable: VUL-CVE-2017-13048
bgp_pmsi_tunnel-oobr	bgp_pmsi_tunnel-oobr.pcap	bgp_pmsi_tunnel-oobr.out -v -c1
bgp_mvpn_6_and_7	bgp_mvpn_6_and_7.pcap		bgp_mvpn_6_and_7.out	-v -c1

# bad packets from Katie Holly
// --- print-rsvp.c ---
            /* the differences between c-type 1 and 7 are minor */
            obj_ptr.rsvp_obj_frr = (const struct rsvp_obj_frr_t *)obj_tptr;
            bw.i = EXTRACT_32BITS(obj_ptr.rsvp_obj_frr->bandwidth);

            switch(rsvp_obj_ctype) {
...
...
                    return-1;
                ND_PRINT((ndo, "%s  Setup Priority: %u, Holding Priority: %u, Hop-limit: %u, Bandwidth: %.10g Mbps",
                       ident,
