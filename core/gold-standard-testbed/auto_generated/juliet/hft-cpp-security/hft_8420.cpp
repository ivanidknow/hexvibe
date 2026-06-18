// Vulnerable: HFT-8420
void CWE124_Buffer_Underwrite__malloc_wchar_t_memcpy_67b_badSink(CWE124_Buffer_Underwrite__malloc_wchar_t_memcpy_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
memcpy(data, source, 100*sizeof(wchar_t));
data[100-1] = L'\0';
printWLine(data);
