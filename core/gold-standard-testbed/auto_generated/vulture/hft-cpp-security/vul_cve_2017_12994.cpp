// Vulnerable: VUL-CVE-2017-12994
telnet-iac-check-oobr	telnet-iac-check-oobr.pcap	telnet-iac-check-oobr.out	-vvv -e
resp_4_infiniteloop	resp_4_infiniteloop.pcap	resp_4_infiniteloop.out	-vvv -e

# RTP tests
// --- print-bgp.c ---
		uint16_t length;

		ND_TCHECK2(tptr[0], 3);

		tlen = len;

...
			    print_unknown_data(ndo, tptr+3,"\n\t      ", length-3);
			}
		    }
