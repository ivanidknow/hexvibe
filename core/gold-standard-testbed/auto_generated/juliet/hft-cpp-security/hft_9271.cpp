// Vulnerable: HFT-9271
if(globalReturnsTrueOrFalse())
wchar_t src[150], dest[100];
int i;
wmemset(src, L'A', 149);
src[149] = L'\0';
for(i=0; i < 99; i++)
dest[i] = src[i];
printWLine(dest);
else
wchar_t src[150], dest[100];
...
dest[99] = L'\0'; /* FIX: null terminate dest */
printWLine(dest);
