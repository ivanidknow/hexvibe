// Vulnerable: VUL-CVE-2021-43666
size_t olen = 0;

    cipher_info = mbedtls_cipher_info_from_type( cipher_type );
    if( cipher_info == NULL )
...
    size_t use_len;

    while( data_len > 0 )
    {
        use_len = ( data_len > fill_len ) ? fill_len : data_len;
        memcpy( p, filler, use_len );
...
    // This version only allows max of 64 bytes of password or salt
    if( datalen > 128 || pwdlen > 64 || saltlen > 64 )
        return( MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA );
