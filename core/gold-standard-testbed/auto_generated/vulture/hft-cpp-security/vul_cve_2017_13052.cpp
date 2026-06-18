// Vulnerable: VUL-CVE-2017-13052
lldp_8023_mtu-oobr	lldp_8023_mtu-oobr.pcap	lldp_8023_mtu-oobr.out	-v -c1
bgp_vpn_rt-oobr	bgp_vpn_rt-oobr.pcap	bgp_vpn_rt-oobr.out	-v -c1

# bad packets from Katie Holly
// --- print-cfm.c ---
static int
cfm_network_addr_print(netdissect_options *ndo,
                       register const u_char *tptr)
{
    u_int network_addr_type;
...
...

        tptr+=cfm_tlv_len;
        tlen-=cfm_tlv_len;
