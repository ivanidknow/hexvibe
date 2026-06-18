// Vulnerable: VUL-CVE-2020-11068
{
        case FRAME_TYPE_JOIN_ACCEPT:
            macMsgJoinAccept.Buffer = payload;
            macMsgJoinAccept.BufSize = size;
...
            getPhy.Attribute = PHY_MAX_PAYLOAD;
            phyParam = RegionGetPhyParam( MacCtx.NvmCtx->Region, &getPhy );
            if( MAX( 0, ( int16_t )( ( int16_t ) size - ( int16_t ) LORA_MAC_FRMPAYLOAD_OVERHEAD ) ) > ( int16_t )phyParam.Value )
            {
                MacCtx.McpsIndication.Status = LORAMAC_EVENT_INFO_STATUS_ERROR;
// --- atecc608a-tnglora-se.c ---
...

    // Determine decryption key
    KeyIdentifier_t encKeyID = NWK_KEY;
