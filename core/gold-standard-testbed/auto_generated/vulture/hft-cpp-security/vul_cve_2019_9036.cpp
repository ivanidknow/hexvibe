// Vulnerable: VUL-CVE-2019-9036
mat_uint8_t comp_buf[32];
    int    err;
    size_t bytesread = 0;

    if ( buf == NULL )
...
        return bytesread;
    }
    while ( matvar->internal->z->avail_out && !matvar->internal->z->avail_in ) {
        matvar->internal->z->avail_in = 1;
        matvar->internal->z->next_in = comp_buf;
...
EXTERN size_t InflateDimensions(mat_t *mat, matvar_t *matvar, void *buf);
EXTERN size_t InflateVarNameTag(mat_t *mat, matvar_t *matvar, void *buf);
EXTERN size_t InflateVarName(mat_t *mat,matvar_t *matvar,void *buf,int N);
