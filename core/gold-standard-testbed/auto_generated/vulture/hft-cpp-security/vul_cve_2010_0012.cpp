// Vulnerable: VUL-CVE-2010-0012
static tr_bool
getfile( char        ** setme,
         const char   * root,
         tr_benc      * path )
{
    tr_bool success = FALSE;
...
    if( tr_bencIsList( path ) )
    {
        struct evbuffer * buf = evbuffer_new( );
        int               n = tr_bencListSize( path );
...
    {
        inf->isMultifile      = 0;
        inf->fileCount        = 1;
