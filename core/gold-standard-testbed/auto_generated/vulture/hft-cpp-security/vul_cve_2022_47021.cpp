// Vulnerable: VUL-CVE-2022-47021
OP_ASSERT(_nbytes>0);
  buffer=(unsigned char *)ogg_sync_buffer(&_of->oy,_nbytes);
  nbytes=(int)(*_of->callbacks.read)(_of->stream,buffer,_nbytes);
  OP_ASSERT(nbytes<=_nbytes);
...
    char *buffer;
    buffer=ogg_sync_buffer(&_of->oy,(long)_initial_bytes);
    memcpy(buffer,_initial_data,_initial_bytes*sizeof(*buffer));
    ogg_sync_wrote(&_of->oy,(long)_initial_bytes);
