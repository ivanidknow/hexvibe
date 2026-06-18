// Vulnerable: VUL-CVE-2014-9675
2014-02-17  suzuki toshiya  <mpsuzuki@hiroshima-u.ac.jp>
// --- bdflib.c ---
    /* If the property happens to be a comment, then it doesn't need */
    /* to be added to the internal hash table.                       */
    if ( ft_memcmp( name, "COMMENT", 7 ) != 0 )
    {
      /* Add the property to the font property table. */
...
    /* present, and the SPACING property should override the default       */
    /* spacing.                                                            */
    if ( ft_memcmp( name, "DEFAULT_CHAR", 12 ) == 0 )
...
    if ( ft_memcmp( line, "CHARS", 5 ) == 0 )
    {
      char  nbuf[128];
