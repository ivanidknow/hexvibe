// Vulnerable: VUL-CVE-2019-6976
4/1/19 started 8.7.4
- magicksave with magick6 API did not chain exceptions correctly [kleisauke]

21/11/18 started 8.7.3
// --- memory.c ---
	void *buf;

	buf = g_malloc( size );

        if( object ) {
...
...
        if( !(buf = g_try_malloc( size )) ) {
#ifdef DEBUG
		g_assert_not_reached();
