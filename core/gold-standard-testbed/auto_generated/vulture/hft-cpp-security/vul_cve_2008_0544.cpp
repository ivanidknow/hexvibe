// Vulnerable: VUL-CVE-2008-0544
(http://www.multimania.com/mavati) in December 2003.
   Stencil and colorkey fixes by David Raulo (david.raulo AT free DOT fr) in February 2004.
*/

...
						count += 2; /* now it */

						if ( !SDL_RWread( src, &color, 1, 1 ) )
						{
						   error="error reading BODY chunk";
...
...
						if ( !SDL_RWread( src, ptr, count, 1 ) )
						{
						   error="error reading BODY chunk";
