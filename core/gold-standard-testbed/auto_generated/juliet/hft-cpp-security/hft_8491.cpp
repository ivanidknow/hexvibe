// Vulnerable: HFT-8491
wchar_t * data;
data = NULL;
data = CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_61b_badSource(data);
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
wcsncpy(data, source, 100-1);
data[100-1] = L'\0';
printWLine(data);
