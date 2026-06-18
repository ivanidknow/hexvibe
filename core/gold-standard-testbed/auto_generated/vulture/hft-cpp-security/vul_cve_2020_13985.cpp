// Vulnerable: VUL-CVE-2020-13985
rpl_instance_t *instance;
  int down;
  uint8_t sender_closer;
  uip_ds6_route_t *route;
...
  }

  sender_closer = UIP_EXT_HDR_OPT_RPL_BUF->senderrank < instance->current_dag->rank;

  PRINTF("RPL: Packet going %s, sender closer %d (%d < %d)\n", down == 1 ? "down" : "up",
...
...
    UIP_EXT_HDR_OPT_RPL_BUF->senderrank = rpl_get_instance(UIP_EXT_HDR_OPT_RPL_BUF->instance)->current_dag->rank;
    uip_ext_len = last_uip_ext_len;
    return RPL_HOP_BY_HOP_LEN;
