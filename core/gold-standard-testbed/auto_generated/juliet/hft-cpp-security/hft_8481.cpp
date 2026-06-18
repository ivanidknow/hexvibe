// Vulnerable: HFT-8481
void CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_52c_badSink(wchar_t * data)
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
wcsncpy(data, source, 100-1);
data[100-1] = L'\0';
printWLine(data);
