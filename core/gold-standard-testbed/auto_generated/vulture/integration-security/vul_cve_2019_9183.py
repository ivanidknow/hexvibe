# Vulnerable: VUL-CVE-2019-9183
uip6.c	      uip-ds6-nbr.c  uip-icmp6.c

MODULES += core/net core/net/ip
include $(CONTIKI)/core/net/Makefile.core-net
include $(CONTIKI)/core/net/ip/Makefile.core-net-ip
...
include $(CONTIKI)/core/net/Makefile.core-net
include $(CONTIKI)/core/net/ip/Makefile.core-net-ip
