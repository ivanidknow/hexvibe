// Vulnerable: VUL-CVE-2017-13033
vtp_asan		vtp_asan.pcap			vtp_asan.out	-v
vtp_asan-2		vtp_asan-2.pcap			vtp_asan-2.out	-v
icmp6_mobileprefix_asan	icmp6_mobileprefix_asan.pcap	icmp6_mobileprefix_asan.out	-v
ip_printroute_asan	ip_printroute_asan.pcap		ip_printroute_asan.out	-v
// --- print-vtp.c ---
 *
 * Reference documentation:
 *  http://www.cisco.com/en/US/tech/tk389/tk689/technologies_tech_note09186a0080094c52.shtml
 *  http://www.cisco.com/warp/public/473/21.html
 *  http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm
 *
...
FRF.16 Frag, seq 193, Flags [Begin, End], UI 08! VTPv69, Message Subset advertisement (0x02), length 2126400013
	Domain name: , Seq number: 0, Config Rev fb499603
	VLAN info status Unknown, type TrCRF, VLAN-id 256, MTU 771, SAID 0x03030303, Name ^C^I^C[|vtp]
