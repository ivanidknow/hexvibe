// Vulnerable: VUL-CVE-2019-19931
goto exit_with_error;

            MmsValue* elementValue = MmsValue_decodeMmsData(buffer, bufPos, dataLength, NULL);

            if (elementValue == NULL)
...

    case 0x85: /* MMS_INTEGER */
        value = MmsValue_newInteger(dataLength * 8);
        memcpy(value->value.integer->octets, buffer + bufPos, dataLength);
...
...
    case 0x86: /* MMS_UNSIGNED */
        value = MmsValue_newUnsigned(dataLength * 8);
        memcpy(value->value.integer->octets, buffer + bufPos, dataLength);
