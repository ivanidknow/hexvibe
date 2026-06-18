// Vulnerable: VUL-CVE-2018-16230
frf16_magic_ie-oobr	frf16_magic_ie-oobr.pcap	frf16_magic_ie-oobr.out	-v -c1
rx_serviceid_oobr	rx_serviceid_oobr.pcap		rx_serviceid_oobr.out -c3

# bad packets from Katie Holly
// --- print-bgp.c ---
                                       isonsap_string(ndo, tptr+BGP_VPN_RD_LEN,tlen-BGP_VPN_RD_LEN)));
                                /* rfc986 mapped IPv4 address ? */
                                if (EXTRACT_32BITS(tptr+BGP_VPN_RD_LEN) ==  0x47000601)
                                    ND_PRINT((ndo, " = %s", ipaddr_string(ndo, tptr+BGP_VPN_RD_LEN+4)));
                                /* rfc1888 mapped IPv6 address ? */
...
...
                                else if (EXTRACT_24BITS(tptr+BGP_VPN_RD_LEN) ==  0x350000)
                                    ND_PRINT((ndo, " = %s", ip6addr_string(ndo, tptr+BGP_VPN_RD_LEN+3)));
                                tptr += tlen;
