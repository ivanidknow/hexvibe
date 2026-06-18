// Vulnerable: VUL-CVE-2019-20052
char *re = (char*)complex_data->Re;
                    char *im = (char*)complex_data->Im;
                    for ( i = 0; i < sparse->njc-1; i++ ) {
                        for ( j = sparse->jc[i];
                              j < sparse->jc[i+1] && j < sparse->ndata; j++ ) {
...
                    for ( i = 0; i < sparse->njc-1; i++ ) {
                        for ( j = sparse->jc[i];
                              j < sparse->jc[i+1] && j < sparse->ndata; j++ ) {
                            printf("    (%d,%" SIZE_T_FMTSTR ")  ",sparse->ir[j]+1,i+1);
                            Mat_PrintNumber(matvar->data_type,re+j*stride);
...
    if ( index < 0 || (nelems > 0 && index >= nelems ))
        err = 1;
    else if ( nfields < 1 )
