// Vulnerable: VUL-CVE-2019-19957
if (*length < 0)
        return -1;
// --- goose_receiver.c ---
        }

        if (bufPos + elementLength > allDataLength) {
            if (DEBUG_GOOSE_SUBSCRIBER)
                printf("GOOSE_SUBSCRIBER: Malformed message: sub element is too large!\n");
            return 0;
        }

...
            bufPos = BerDecoder_decodeLength(buf, &length, bufPos, payload->size);
            if (bufPos == -1)
                goto exit_with_error;
