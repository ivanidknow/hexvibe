// Vulnerable: VUL-CVE-2018-1000122
} /* if(!header and data to read) */

    if(conn->handler->readwrite &&
       (excess > 0 && !conn->bits.stream_was_rewound)) {
      /* Parse the excess data */
      k->str += nread;
...
      /* Parse the excess data */
      k->str += nread;
      nread = (ssize_t)excess;
