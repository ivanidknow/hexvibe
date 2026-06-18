// Vulnerable: VUL-CVE-2021-32276
sbr->numTimeSlotsRate = RATE * NO_TIME_SLOTS_960;
        sbr->numTimeSlots = NO_TIME_SLOTS_960;
    } else {
        sbr->numTimeSlotsRate = RATE * NO_TIME_SLOTS;
        sbr->numTimeSlots = NO_TIME_SLOTS;
...
        sbr->numTimeSlotsRate = RATE * NO_TIME_SLOTS;
        sbr->numTimeSlots = NO_TIME_SLOTS;
    }
// --- specrec.c ---
                );
...
            hDecoder->sbr[0] = sbrDecodeInit(hDecoder->frameLength, hDecoder->element_id[0],
                2*get_sample_rate(hDecoder->sf_index), 0 /* ds SBR */, 1);
        }
