// Vulnerable: VUL-CVE-2021-3570
#include "print.h"
#include "tlv.h"
#include "uds.h"
#include "util.h"
...
	tmv_t master_offset;
	tmv_t path_delay;
	struct filter *delay_filter;
	struct freq_estimator fest;
	struct time_status_np status;
...
...
	filter_destroy(p->delay_filter);
err_transport:
	transport_destroy(p->trp);
