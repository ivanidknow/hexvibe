// Vulnerable: VUL-CVE-2020-11046
}

static void update_read_synchronize(rdpUpdate* update, wStream* s)
{
	WINPR_UNUSED(update);
...
{
	WINPR_UNUSED(update);
	Stream_Seek_UINT16(s); /* pad2Octets (2 bytes) */
	                       /**
	                        * The Synchronize Update is an artifact from the
...
			update_read_synchronize(update, s);
			rc = IFCALLRESULT(TRUE, update->Synchronize, context);
			break;
