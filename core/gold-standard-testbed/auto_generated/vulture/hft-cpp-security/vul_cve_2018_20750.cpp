// Vulnerable: VUL-CVE-2018-20750
/* strftime() */
#include <time.h>

#ifdef LIBVNCSERVER_WITH_WEBSOCKETS
...
       will safely be allocated since this check will never trigger and malloc() can digest length+1
       without problems as length is a uint32_t.
    */
    if(length == SIZE_MAX) {
...
       without problems as length is a uint32_t.
...
    if(length == SIZE_MAX) {
	rfbErr("rfbProcessFileTransferReadBuffer: too big file transfer length requested: %u", (unsigned int)length);
	rfbCloseClient(cl);
