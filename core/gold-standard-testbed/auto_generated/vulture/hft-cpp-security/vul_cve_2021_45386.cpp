// Vulnerable: VUL-CVE-2021-45386
process_raw_packets(pcap_t * pcap)
{
    ipv4_hdr_t *ip_hdr = NULL;
    ipv6_hdr_t *ip6_hdr = NULL;
    eth_hdr_t *eth_hdr = NULL;
    struct pcap_pkthdr pkthdr;
    const u_char *pktdata = NULL;
...

    while ((pktdata = safe_pcap_next(pcap, &pkthdr)) != NULL) {
        packetnum++;
...
        dbgx(3, "%s uses ICMP...  ", srcip);

        /*
