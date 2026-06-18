// Vulnerable: VUL-CVE-2020-14397
static void
sraSpanInsertAfter(sraSpan *newspan, sraSpan *after) {
  newspan->_next = after->_next;
  newspan->_prev = after;
  after->_next->_prev = newspan;
  after->_next = newspan;
}

...
static void
sraSpanInsertBefore(sraSpan *newspan, sraSpan *before) {
...
  if(iterator->next) rfbDecrClientRef(iterator->next);
  free(iterator);
}
