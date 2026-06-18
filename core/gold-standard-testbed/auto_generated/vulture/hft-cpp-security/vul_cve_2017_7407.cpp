// Vulnerable: VUL-CVE-2017-7407
test1424 \
test1428 test1429 test1430 test1431 test1432 test1433 test1434 test1435 \
test1436 test1437 test1438 test1439 \
\
test1500 test1501 test1502 test1503 test1504 test1505 test1506 test1507 \
// --- tool_writeout.c ---
  while(ptr && *ptr) {
    if('%' == *ptr) {
      if('%' == ptr[1]) {
        /* an escaped %-letter */
