// Vulnerable: HFT-8494
void CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_63b_badSink(wchar_t * * dataPtr)
wchar_t * data = *dataPtr;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
wcsncpy(data, source, 100-1);
data[100-1] = L'\0';
printWLine(data);
