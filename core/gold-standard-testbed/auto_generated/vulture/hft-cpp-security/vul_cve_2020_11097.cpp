// Vulnerable: VUL-CVE-2020-11097
#define TAG WINPR_TAG("sspi.NTLM")

static const char* const AV_PAIR_STRINGS[] = {
	"MsvAvEOL",           "MsvAvNbComputerName", "MsvAvNbDomainName", "MsvAvDnsComputerName",
	"MsvAvDnsDomainName", "MsvAvDnsTreeName",    "MsvAvFlags",        "MsvAvTimestamp",
	"MsvAvRestrictions",  "MsvAvTargetName",     "MsvChannelBindings"
};

static BOOL ntlm_av_pair_check(NTLM_AV_PAIR* pAvPair, size_t cbAvPair);
static NTLM_AV_PAIR* ntlm_av_pair_next(NTLM_AV_PAIR* pAvPairList, size_t* pcbAvPairList);

...
		AvPairsCount++; /* MsvAvDnsTreeName */
		AvPairsValueLength += ntlm_av_pair_get_len(AvDnsTreeName);
	}
