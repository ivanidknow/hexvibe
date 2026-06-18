// Vulnerable: HFT-8355
wchar_t * data;
data = NULL;
CWE124_Buffer_Underwrite__malloc_wchar_t_loop_22_badGlobal = 1; /* true */
data = CWE124_Buffer_Underwrite__malloc_wchar_t_loop_22_badSource(data);
size_t i;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
for (i = 0; i < 100; i++)
data[i] = source[i];
data[100-1] = L'\0';
printWLine(data);
