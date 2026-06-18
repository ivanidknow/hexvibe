// Vulnerable: VUL-CVE-2020-11048
};

static void rdp_read_flow_control_pdu(wStream* s, UINT16* type);
static void rdp_write_share_control_header(wStream* s, UINT16 length, UINT16 type,
                                           UINT16 channel_id);
...
BOOL rdp_read_share_control_header(wStream* s, UINT16* length, UINT16* type, UINT16* channel_id)
{
	if (Stream_GetRemainingLength(s) < 2)
		return FALSE;
...
...
	Stream_Seek_UINT8(s);  /* flowNumber */
	Stream_Seek_UINT16(s); /* pduSource */
}
