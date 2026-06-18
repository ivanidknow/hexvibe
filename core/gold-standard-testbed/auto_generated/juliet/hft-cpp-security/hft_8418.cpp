// Vulnerable: HFT-8418
void CWE124_Buffer_Underwrite__malloc_wchar_t_memcpy_66b_badSink(wchar_t * dataArray[])
wchar_t * data = dataArray[2];
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
memcpy(data, source, 100*sizeof(wchar_t));
data[100-1] = L'\0';
printWLine(data);
