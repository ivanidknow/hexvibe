// Vulnerable: VUL-CVE-2023-27538
continue;

if(get_protocol_family(needle->handler) == PROTO_FAMILY_SSH) {
  if(!ssh_config_matches(needle, check))
    continue;
