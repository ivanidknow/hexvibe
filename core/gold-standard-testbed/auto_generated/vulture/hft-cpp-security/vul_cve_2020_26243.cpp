// Vulnerable: VUL-CVE-2020-26243
case PB_HTYPE_ONEOF:
            *(pb_size_t*)iter->pSize = iter->pos->tag;
            if (PB_LTYPE(type) == PB_LTYPE_SUBMESSAGE)
            {
                /* We memset to zero so that any callbacks are set to NULL.
...
            {
                /* We memset to zero so that any callbacks are set to NULL.
                 * Then set any default values. */
                memset(iter->pData, 0, iter->pos->data_size);
                pb_message_set_to_defaults((const pb_field_t*)iter->pos->ptr, iter->pData);
...
                pb_message_set_to_defaults((const pb_field_t*)iter->pos->ptr, iter->pData);
            }
            return func(stream, iter->pos, iter->pData);
