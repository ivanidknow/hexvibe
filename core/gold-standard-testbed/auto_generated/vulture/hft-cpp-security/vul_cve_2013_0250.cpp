// Vulnerable: VUL-CVE-2013-0250
hash_param.type = siBuffer;
hash_param.data = 0;
hash_param.len = 0;

hash_slot = PK11_GetBestSlot(hash_to_nss[instance->crypto_hash_type], NULL);
