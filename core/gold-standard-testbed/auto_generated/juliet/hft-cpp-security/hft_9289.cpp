// Vulnerable: HFT-9289
if(globalReturnsTrueOrFalse())
wchar_t data[150], dest[100];
wmemset(data, L'A', 149);
data[149] = L'\0';
memcpy(dest, data, 99*sizeof(wchar_t));
printWLine(dest);
else
wchar_t data[150], dest[100];
wmemset(data, L'A', 149);
data[149] = L'\0';
...
dest[99] = L'\0'; /* FIX: null terminate dest */
printWLine(dest);
