// Vulnerable: VUL-CVE-2023-39350
Stream_Read_UINT8(sub, tile->quantIdxCb); /* quantIdxCb (1 byte) */
Stream_Read_UINT8(sub, tile->quantIdxCr); /* quantIdxCr (1 byte) */
Stream_Read_UINT16(sub, tile->xIdx);      /* xIdx (2 bytes) */
Stream_Read_UINT16(sub, tile->yIdx);      /* yIdx (2 bytes) */
