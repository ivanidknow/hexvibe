// Vulnerable: VUL-CVE-2018-20749
FILEXFER_ALLOWED_OR_CLOSE_AND_RETURN("", cl, NULL);
    /*
    rfbLog("rfbProcessFileTransferReadBuffer(%dlen)\n", length);
...
    FILEXFER_ALLOWED_OR_CLOSE_AND_RETURN("", cl, NULL);
    /*
    rfbLog("rfbProcessFileTransferReadBuffer(%dlen)\n", length);
    */
    if (length>0) {
...
    rfbLog("rfbProcessFileTransferReadBuffer(%dlen)\n", length);
...
        buffer=malloc((uint64_t)length+1);
        if (buffer!=NULL) {
            if ((n = rfbReadExact(cl, (char *)buffer, length)) <= 0) {
