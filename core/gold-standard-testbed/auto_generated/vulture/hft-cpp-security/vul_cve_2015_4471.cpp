// Vulnerable: VUL-CVE-2015-4471
2015-01-17  Stuart Caie <kyzer@4u.net>
// --- lzxd.c ---
	  /* read 1-16 (not 0-15) bits to align to bytes */
	  ENSURE_BITS(16);
	  if (bits_left > 16) i_ptr -= 2;
	  bits_left = 0; bit_buffer = 0;
