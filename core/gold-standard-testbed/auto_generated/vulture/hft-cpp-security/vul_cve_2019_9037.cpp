// Vulnerable: VUL-CVE-2019-9037
return;
    else if ( mat->version == MAT_FT_MAT5 )
        Read5(mat,matvar);
#if defined(MAT73) && MAT73
    else if ( mat->version == MAT_FT_MAT73 )
...
#endif
    else if ( mat->version == MAT_FT_MAT4 )
        Read4(mat,matvar);
    return;
}
...
/** @if mat_devman
 * @brief Reads the header information for the next MAT variable
 *
