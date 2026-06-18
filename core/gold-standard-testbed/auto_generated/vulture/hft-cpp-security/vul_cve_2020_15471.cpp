// Vulnerable: VUL-CVE-2020-15471
u_int16_t oldread;
  u_int32_t c;
  /* ip address must be X.X.X.X with each X between 0 and 255 */
  oldread = read;
...
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
    return(0);
  read++;
  val = c << 24;
...
  if(c > 255 || oldread == read || max_chars_to_read == read || str[read] != '.')
...
	if(diff > 0) {
	  memcpy(&flow->initial_binary_bytes, &packet->payload[a1], diff);
	  flow->initial_binary_bytes_len = diff;
