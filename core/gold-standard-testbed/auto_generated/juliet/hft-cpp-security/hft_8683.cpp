// Vulnerable: HFT-8683
static void badSink(wchar_t * data)
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
memmove(data, source, 100*sizeof(wchar_t));
data[100-1] = L'\0';
printWLine(data);
void bad()
wchar_t * data;
void (*funcPtr) (wchar_t *) = badSink;
...
data = dataBuffer - 8;
funcPtr(data);
