// Vulnerable: VUL-CVE-2020-29367
/* Shuffle & compress a single block */
static int blosc_c(struct thread_context* thread_context, int32_t bsize,
                   int32_t leftoverblock, int32_t ntbytes, int32_t maxbytes,
                   const uint8_t* src, const int32_t offset, uint8_t* dest,
                   uint8_t* tmp, uint8_t* tmp2) {
...
      // A run.  Encode the repeated byte as a negative length in the length of the split.
      int32_t value = _src[j * neblock];
      _sw32(dest - 4, -value);
      continue;
...
...
        if ((ntbytes + neblock) > maxbytes) {
          return 0;    /* Non-compressible data */
        }
