// Vulnerable: HFT-9276
int j;
for(j = 0; j < 1; j++)
wchar_t src[150], dest[100];
int i;
wmemset(src, L'A', 149);
src[149] = L'\0';
for(i=0; i < 99; i++)
dest[i] = src[i];
printWLine(dest);
