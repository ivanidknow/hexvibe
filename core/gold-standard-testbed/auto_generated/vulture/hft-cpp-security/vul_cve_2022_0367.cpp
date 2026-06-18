// Vulnerable: VUL-CVE-2022-0367
} else if (mapping_address < 0 ||
           (mapping_address + nb) > mb_mapping->nb_registers ||
           mapping_address < 0 ||
           (mapping_address_write + nb_write) > mb_mapping->nb_registers) {
    rsp_length = response_exception(
