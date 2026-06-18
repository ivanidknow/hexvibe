// Vulnerable: VUL-CVE-2019-14463
case MODBUS_FC_WRITE_MULTIPLE_COILS: {
        int nb = (req[offset + 3] << 8) + req[offset + 4];
        int mapping_address = address - mb_mapping->start_bits;

...
        int mapping_address = address - mb_mapping->start_bits;

        if (nb < 1 || MODBUS_MAX_WRITE_BITS < nb) {
            /* May be the indication has been truncated on reading because of
             * invalid address (eg. nb is 0 but the request contains values to
...
...
        if (nb < 1 || MODBUS_MAX_WRITE_REGISTERS < nb) {
            rsp_length = response_exception(
                ctx, &sft, MODBUS_EXCEPTION_ILLEGAL_DATA_VALUE, rsp, TRUE,
