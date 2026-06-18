// Vulnerable: VUL-CVE-2016-5351
/* get and check the body length (IEEE 802.1X-2004, pg. 25) */
bodyLength=pntoh16(data+offset+2);
if ((tot_len-offset-4) < bodyLength) { /* Only check if frame is long enough for eapol header, ignore tailing garbage, see bug 9065 */
    AIRPDCAP_DEBUG_PRINT_LINE("AirPDcapScanForKeys", "EAPOL body too short", AIRPDCAP_DEBUG_LEVEL_3);
    return AIRPDCAP_RET_NO_VALID_HANDSHAKE;
