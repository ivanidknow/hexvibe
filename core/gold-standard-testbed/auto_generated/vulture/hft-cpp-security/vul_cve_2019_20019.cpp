// Vulnerable: VUL-CVE-2019-20019
mat_uint32_t len = uncomp_buf[1];

                        if ( len % 8 > 0 )
                            len = len+(8-(len % 8));
                        cells[i]->name = (char*)malloc(len+1);
                        nbytes -= len;
                        if ( NULL != cells[i]->name ) {
...

        for ( i = 0; i < nelems; i++ ) {
            int cell_bytes_read,name_len;
...
                    len_pad = len + 8 - (len % 8);
                matvar->name = (char*)malloc(len_pad + 1);
                if ( NULL != matvar->name ) {
