// Vulnerable: HFT-8382
void CWE124_Buffer_Underwrite__malloc_wchar_t_loop_67b_badSink(CWE124_Buffer_Underwrite__malloc_wchar_t_loop_67_structType myStruct)
wchar_t * data = myStruct.structFirst;
size_t i;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
for (i = 0; i < 100; i++)
data[i] = source[i];
data[100-1] = L'\0';
printWLine(data);
