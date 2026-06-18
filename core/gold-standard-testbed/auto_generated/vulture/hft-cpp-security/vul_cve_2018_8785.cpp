// Vulnerable: VUL-CVE-2018-8785
struct _ZGFX_TOKEN
{
	int prefixLength;
	int prefixCode;
	int valueBits;
	int tokenType;
	UINT32 valueBase;
};
...
};
typedef struct _ZGFX_TOKEN ZGFX_TOKEN;
...
...

#endif /* FREERDP_CODEC_ZGFX_H */
