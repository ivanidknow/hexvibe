// Vulnerable: VUL-CVE-2013-6473
CHANGES IN V1.0.47

	- pdftopdf: Fixed typo in initialization which sets the default
	  value page border to an undefined value. Thanks to Helge
// --- urftopdf.cpp ---
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>   // ntohl
...
        info->bpp = bpp;
...

    try {
        pixel_container.resize(pixel_size);
