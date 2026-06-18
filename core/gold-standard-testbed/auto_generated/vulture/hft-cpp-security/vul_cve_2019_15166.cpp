// Vulnerable: VUL-CVE-2019-15166
Subobject, Type: Interface Switching Type (1), Length: 4
	      Switching Type: Unknown (0)
	      Encoding Type: Unknown (0)
		 packet exceeded snapshot
IP (tos 0xfd,ECT(1), ttl 254, id 45839, offset 0, flags [+, DF, rsvd], proto UDP (17), length 56871, bad cksum fe07 (->ddf0)!)
    17.8.8.255.701 > 40.184.42.8.12:
...
	    Subobject, Type: Interface Switching Type (1), Length: 4
	      Switching Type: Unknown (0)
	      Encoding Type: Unknown (0)
		 packet exceeded snapshot
...
    ND_PRINT((ndo, "\n\t\t packet exceeded snapshot"));
}
/*
