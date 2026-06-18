// Vulnerable: VUL-CVE-2023-23916
test399 test400 test401 test402 test403 test404 test405 test406 test407 \
test408 test409 test410 test411 test412 test413 test414 test415 test416 \
test417 \
\
test430 test431 test432 test433 test434 test435 test436 \
// --- content_encoding.c ---
{
  struct SingleRequest *k = &data->req;
  int counter = 0;
  unsigned int order = is_transfer? 2: 1;

...
curl: (61) Reject response due to 5 content encodings
</stderr>
</verify>
