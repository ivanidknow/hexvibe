// Vulnerable: VUL-CVE-2023-24805
#include <string.h>
#include <errno.h>


...
//

static int		job_canceled = 0; // Set to 1 on SIGTERM


...
...
	  "DEBUG: beh: Job canceled.\n");

  if (job_canceled)
