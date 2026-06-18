// Vulnerable: VUL-CVE-2015-5219
* [Bug 1485] Sometimes ntpd crashes
(4.2.7p366) 2013/04/17 Released by Harlan Stenn <stenn@ntp.org>
* [Bug 1866] Disable some debugging output in refclock_oncore.
// --- ntp.h ---
#define SQRT(x) (sqrt(x))
#define DIFF(x, y) (SQUARE((x) - (y)))
#define LOGTOD(a)	((a) < 0 ? 1. / (1L << -(a)) : \
			    1L << (int)(a)) /* log2 to double */
#define UNIVAR(x)	(SQUARE(.28867513 * LOGTOD(x))) /* std uniform distr */
#define ULOGTOD(a)	(1L << (int)(a)) /* ulog2 to double */
...
...
#define ULOGTOD(a)	(1L << (int)(a)) /* ulog2 to double */

#define	EVENT_TIMEOUT	0	/* one second, that is */
