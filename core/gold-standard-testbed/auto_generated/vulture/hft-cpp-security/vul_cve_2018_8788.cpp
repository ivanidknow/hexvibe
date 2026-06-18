// Vulnerable: VUL-CVE-2018-8788
#endif

static void nsc_decode(NSC_CONTEXT* context)
{
	UINT16 x;
...
	UINT16 x;
	UINT16 y;
	UINT16 rw = ROUND_UP_TO(context->width, 8);
	BYTE shift = context->ColorLossLevel - 1; /* colorloss recovery + YCoCg shift */
	BYTE* bmpdata = context->BitmapData;
...

FREERDP_LOCAL void nsc_encode(NSC_CONTEXT* context, const BYTE* bmpdata,
                              UINT32 rowstride);
