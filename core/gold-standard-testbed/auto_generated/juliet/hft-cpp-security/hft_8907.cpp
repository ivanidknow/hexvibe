// Vulnerable: HFT-8907
wchar_t * data;
wchar_t dataBuffer[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
CWE124_Buffer_Underwrite__wchar_t_declare_memmove_68_badData = data;
CWE124_Buffer_Underwrite__wchar_t_declare_memmove_68b_badSink();
