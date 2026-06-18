// Vulnerable: HFT-8525
a C++ namespace, it doesn't need a globally unique name. */
int badGlobal = 0;
char * badSource(char * data);
void bad()
char * data;
data = NULL;
badGlobal = 1; /* true */
data = badSource(data);
char source[100];
memset(source, 'C', 100-1); /* fill with 'C's */
...
printLine(data);
;
