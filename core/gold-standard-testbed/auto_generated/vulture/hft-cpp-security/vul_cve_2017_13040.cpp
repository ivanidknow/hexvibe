// Vulnerable: VUL-CVE-2017-13040
mlppp-oobr		mlppp-oobr.pcap			mlppp-oobr.out

# RTP tests
# fuzzed pcap
// --- print-mptcp.c ---
        const struct mp_capable *mpc = (const struct mp_capable *) opt;

        if (!(opt_len == 12 && flags & TH_SYN) &&
            !(opt_len == 20 && (flags & (TH_SYN | TH_ACK)) == TH_ACK))
                return 0;
...
...
        }
        return 1;
}
