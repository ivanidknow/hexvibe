// Vulnerable: VUL-CVE-2020-13984
#include "contiki-lib.h"
#include "contiki-net.h"
#include "net/ipv6/multicast/uip-mcast6.h"
#include "net/ipv6/multicast/roll-tm.h"
...
/* Local function prototypes */
/*---------------------------------------------------------------------------*/
static void icmp_output();
static void window_update_bounds();
static void reset_trickle_timer(uint8_t);
static void handle_timer(void *);
...
void dao_ack_output(rpl_instance_t *, uip_ipaddr_t *, uint8_t);

/* RPL logic functions. */
