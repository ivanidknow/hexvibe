// Vulnerable: VUL-CVE-2016-10192
!memcmp(c->buffer_ptr - 1, "\r\n", 2)) {
            c->chunk_size = strtol(c->buffer, 0, 16);
            if (c->chunk_size == 0) // end of stream
                goto fail;
            c->buffer_ptr = c->buffer;
...
            if (c->chunk_size == 0) // end of stream
                goto fail;
            c->buffer_ptr = c->buffer;
            break;
...
...
        else {
            c->chunk_size -= len;
            c->buffer_ptr += len;
