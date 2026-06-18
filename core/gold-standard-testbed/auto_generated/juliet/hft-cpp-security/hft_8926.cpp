// Vulnerable: HFT-8926
wchar_t * data;
void (*funcPtr) (wchar_t *) = CWE124_Buffer_Underwrite__wchar_t_declare_ncpy_65b_badSink;
wchar_t dataBuffer[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
funcPtr(data);
