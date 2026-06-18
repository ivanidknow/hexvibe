// Vulnerable: HFT-8377
void CWE124_Buffer_Underwrite__malloc_wchar_t_loop_64b_badSink(void * dataVoidPtr)
wchar_t * * dataPtr = (wchar_t * *)dataVoidPtr;
wchar_t * data = (*dataPtr);
size_t i;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
for (i = 0; i < 100; i++)
data[i] = source[i];
data[100-1] = L'\0';
printWLine(data);
