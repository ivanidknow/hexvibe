// Vulnerable: HFT-9266
if(staticFive==5)
wchar_t src[150], dest[100];
int i;
wmemset(src, L'A', 149);
src[149] = L'\0';
for(i=0; i < 99; i++)
dest[i] = src[i];
printWLine(dest);
