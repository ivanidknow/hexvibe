// Vulnerable: VUL-CVE-2017-18922
#define B64LEN(__x) (((__x + 2) / 3) * 12 / 3)
#define WSHLENMAX 14  /* 2 + sizeof(uint64_t) + sizeof(uint32_t) */

enum {
...
typedef int (*wsDecodeFunc)(rfbClientPtr cl, char *dst, int len);

typedef struct ws_ctx_s {
    char codeBufDecode[B64LEN(UPDATE_BUF_SIZE) + WSHLENMAX]; /* base64 + maximum frame header length */
	char codeBufEncode[B64LEN(UPDATE_BUF_SIZE) + WSHLENMAX]; /* base64 + maximum frame header length */
	char readbuf[8192];
...

    if (wsctx && wsctx->readbuflen)
      return TRUE;
