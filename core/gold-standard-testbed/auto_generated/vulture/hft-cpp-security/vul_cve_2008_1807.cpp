// Vulnerable: VUL-CVE-2008-1807
it's always possible to manually select an Apple Unicode cmap if
      desired.

    - Improved Mac support.
// --- ChangeLog ---
2008-06-06  Werner Lemberg  <wl@gnu.org>
// --- ftstream.c ---
/*    I/O stream support (body).                                           */
/*                                                                         */
/*  Copyright 2000-2001, 2002, 2004, 2005, 2006 by                         */
/*  David Turner, Robert Wilhelm, and Werner Lemberg.                      */
...
    if ( idx < 0 || idx > table->max_elems )
    {
      FT_ERROR(( "ps_table_add: invalid index\n" ));
