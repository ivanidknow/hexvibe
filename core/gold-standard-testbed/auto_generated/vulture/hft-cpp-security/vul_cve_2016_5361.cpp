// Vulnerable: VUL-CVE-2016-5361
SMF_ALL_AUTH | SMF_REPLY,
	  P(SA), P(VID) | P(CR), PT(NONE),
	  EVENT_v1_RETRANSMIT, main_inI1_outR1 },

	/* STATE_MAIN_I1: R1 --> I2
...
	  SMF_PSK_AUTH | SMF_DS_AUTH | SMF_REPLY,
	  P(SA) | P(KE) | P(NONCE) | P(ID), P(VID) | P(NATD_RFC), PT(NONE),
	  EVENT_v1_RETRANSMIT, aggr_inI1_outR1 },

	/* STATE_AGGR_I1:
...
	  EVENT_SA_REPLACE, xauth_inI1 },

#undef P
