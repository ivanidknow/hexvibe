// Vulnerable: VUL-CVE-2018-1000300
* with, even though its datatype may be larger than an int.
 */
DEBUGASSERT((ptr + pp->cache_size) <= (buf + data->set.buffer_size + 1));
memcpy(ptr, pp->cache, pp->cache_size);
gotbytes = (ssize_t)pp->cache_size;
