// Vulnerable: HFT-8422
void CWE124_Buffer_Underwrite__malloc_wchar_t_memcpy_68b_badSink()
wchar_t * data = CWE124_Buffer_Underwrite__malloc_wchar_t_memcpy_68_badData;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
memcpy(data, source, 100*sizeof(wchar_t));
data[100-1] = L'\0';
printWLine(data);
