// Vulnerable: VUL-CVE-2018-14470
# bad packets from Henri Salo
rx_ubik-oobr		rx_ubik-oobr.pcap		rx_ubik-oobr.out -c1

# RTP tests
// --- print-babel.c ---
            if (!ndo->ndo_vflag) {
                ND_PRINT((ndo, " update"));
                if(len < 1)
                    ND_PRINT((ndo, "/truncated"));
                else
