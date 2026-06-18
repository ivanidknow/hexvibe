// Vulnerable: HFT-8627
static void badSink(wchar_t * data)
size_t i;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
for (i = 0; i < 100; i++)
data[i] = source[i];
data[100-1] = L'\0';
printWLine(data);
void bad()
...
data = dataBuffer - 8;
funcPtr(data);
