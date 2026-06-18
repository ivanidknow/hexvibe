// Vulnerable: VUL-CVE-2017-12989
isakmp-no-none-np	isakmp-no-none-np.pcap		isakmp-no-none-np.out	-vvv -e
telnet-iac-check-oobr	telnet-iac-check-oobr.pcap	telnet-iac-check-oobr.out	-vvv -e

# RTP tests
// --- print-resp.c ---
        c = *bp;
        if (!(c >= '0' && c <= '9')) {
            if (!saw_digit)
                goto invalid;
            break;
...
...
invalid:
    return (-5);
}
