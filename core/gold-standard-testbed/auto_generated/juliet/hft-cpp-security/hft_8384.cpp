// Vulnerable: HFT-8384
void CWE124_Buffer_Underwrite__malloc_wchar_t_loop_68b_badSink()
wchar_t * data = CWE124_Buffer_Underwrite__malloc_wchar_t_loop_68_badData;
size_t i;
wchar_t source[100];
wmemset(source, L'C', 100-1); /* fill with 'C's */
source[100-1] = L'\0'; /* null terminate */
for (i = 0; i < 100; i++)
data[i] = source[i];
data[100-1] = L'\0';
printWLine(data);
