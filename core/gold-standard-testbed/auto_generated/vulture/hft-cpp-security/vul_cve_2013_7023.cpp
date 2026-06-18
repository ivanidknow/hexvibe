// Vulnerable: VUL-CVE-2013-7023
void* new_buffer = av_fast_realloc(pc->buffer, &pc->buffer_size, (*buf_size) + pc->index + FF_INPUT_BUFFER_PADDING_SIZE);

        if(!new_buffer)
            return AVERROR(ENOMEM);
        pc->buffer = new_buffer;
...
        if(!new_buffer)
            return AVERROR(ENOMEM);
        pc->buffer = new_buffer;
        memcpy(&pc->buffer[pc->index], *buf, *buf_size);
...
...
            return AVERROR(ENOMEM);
        pc->buffer = new_buffer;
        if (next > -FF_INPUT_BUFFER_PADDING_SIZE)
