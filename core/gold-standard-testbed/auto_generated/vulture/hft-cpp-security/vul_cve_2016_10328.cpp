// Vulnerable: VUL-CVE-2016-10328
2016-12-15  Werner Lemberg  <wl@gnu.org>
// --- cffparse.c ---
        FT_UInt                   code;
        FT_UInt                   num_args = (FT_UInt)
                                             ( parser->top - parser->stack );
        const CFF_Field_Handler*  field;

...


        *parser->top = p;
...
        code = v;
        if ( v == 12 )
        {
