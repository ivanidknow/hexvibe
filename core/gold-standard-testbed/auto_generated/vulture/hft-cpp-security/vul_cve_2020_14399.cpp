// Vulnerable: VUL-CVE-2020-14399
{
  rfbSetPixelFormatMsg spf;
  char buf[sz_rfbSetEncodingsMsg + MAX_ENCODINGS * 4];

  rfbSetEncodingsMsg *se = (rfbSetEncodingsMsg *)buf;
  uint32_t *encs = (uint32_t *)(&buf[sz_rfbSetEncodingsMsg]);
  int len = 0;
  rfbBool requestCompressLevel = FALSE;
...
  se->nEncodings = rfbClientSwap16IfLE(se->nEncodings);

  if (!WriteToRFBServer(client, buf, len)) return FALSE;

  return TRUE;
