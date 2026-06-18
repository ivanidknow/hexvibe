// Vulnerable: VUL-CVE-2020-11047
WLog_VRB(AUTODETECT_TAG, "received Bandwidth Measure Results PDU");
Stream_Read_UINT32(s, rdp->autodetect->bandwidthMeasureTimeDelta); /* timeDelta (4 bytes) */
Stream_Read_UINT32(s, rdp->autodetect->bandwidthMeasureByteCount); /* byteCount (4 bytes) */
