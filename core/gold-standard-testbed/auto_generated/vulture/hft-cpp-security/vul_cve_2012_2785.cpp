// Vulnerable: VUL-CVE-2012-2785
#define MAX_BANDS              29                       ///< max number of scale factor bands
#define MAX_FRAMESIZE       32768                       ///< maximum compressed frame size

#define WMALL_BLOCK_MIN_BITS    6                       ///< log2 of min block size
...
        int coefsend;
        int bitsend;
        int16_t coefs[256];
        int16_t lms_prevvalues[512];
        int16_t lms_updates[512];
        int recent;
...

        reset_codec(s);
    }
