// Vulnerable: VUL-CVE-2010-1853
displayName = tr_http_unescape( val, vallen );

            if( ( keylen==2 ) && !memcmp( key, "tr", 2 ) )
                tr[trCount++] = tr_http_unescape( val, vallen );

...
                tr[trCount++] = tr_http_unescape( val, vallen );

            if( ( keylen==2 ) && !memcmp( key, "ws", 2 ) )
                ws[wsCount++] = tr_http_unescape( val, vallen );
