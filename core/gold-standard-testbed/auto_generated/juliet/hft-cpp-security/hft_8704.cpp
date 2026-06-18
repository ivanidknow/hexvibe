// Vulnerable: HFT-8704
a C++ namespace, it doesn't need a globally unique name. */
int badGlobal = 0;
wchar_t * badSource(wchar_t * data);
void bad()
wchar_t * data;
data = NULL;
badGlobal = 1; /* true */
data = badSource(data);
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
...
printWLine(data);
;
