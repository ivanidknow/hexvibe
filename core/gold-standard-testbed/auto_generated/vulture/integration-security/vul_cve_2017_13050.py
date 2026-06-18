# Vulnerable: VUL-CVE-2017-13050
rsvp_uni-oobr-2	rsvp_uni-oobr-2.pcap	rsvp_uni-oobr-2.out	-v -c1
rsvp_uni-oobr-3	rsvp_uni-oobr-3.pcap	rsvp_uni-oobr-3.out	-v -c3

# bad packets from Katie Holly
// --- kday2.out ---
IP (tos 0x0, ttl 64, id 36752, offset 0, flags [DF], proto TCP (6), length 399, bad cksum a46b (->a474)!)
    204.0.55.10.323 > 204.9.54.80.55936: Flags [P.], cksum 0xc9b6 (incorrect -> 0x8900), seq 3589495407:3589495754, ack 370428050, win 1040, options [nop,nop,TS val 2364757411 ecr 3084508609], length 347
	RPKI-RTRv177, Unknown PDU (100), length: 60
	  0x0000:  b164 003c 0000 003c 0000 00ff ff1f 1b70
	  0x0010:  f857 ee68 4dfd 4d5f d9bd c709 30ac 8176
	  0x0020:  b36d cc11 3abf 1291 f106 4ede 61f4 6297
...
	RPKI-RTRv115, Error Report PDU (10), length: 66
	[|RPKI-RTR]
EXIT CODE 00000100
