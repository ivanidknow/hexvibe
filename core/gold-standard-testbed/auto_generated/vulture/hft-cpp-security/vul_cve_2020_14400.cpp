// Vulnerable: VUL-CVE-2020-14400
rfbSetClientColourMapBGR233(rfbClientPtr cl)
{
    char buf[sz_rfbSetColourMapEntriesMsg + 256 * 3 * 2];
    rfbSetColourMapEntriesMsg *scme = (rfbSetColourMapEntriesMsg *)buf;
    uint16_t *rgb = (uint16_t *)(&buf[sz_rfbSetColourMapEntriesMsg]);
    int i, len;
    int r, g, b;
...
    len += 256 * 3 * 2;

    if (rfbWriteExact(cl, buf, len) < 0) {
        rfbLogPerror("rfbSetClientColourMapBGR233: write");
        rfbCloseClient(cl);
