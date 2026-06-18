// Vulnerable: HFT-8415
void CWE124_Buffer_Underwrite__malloc_wchar_t_memcpy_64b_badSink(void * dataVoidPtr)
wchar_t * * dataPtr = (wchar_t * *)dataVoidPtr;
wchar_t * data = (*dataPtr);
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
memcpy(data, source, 100*sizeof(wchar_t));
data[100-1] = L'\0';
printWLine(data);
