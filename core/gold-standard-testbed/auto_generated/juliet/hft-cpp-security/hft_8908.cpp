// Vulnerable: HFT-8908
void bad()
wchar_t * data;
wchar_t dataBuffer[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
const CWE124_Buffer_Underwrite__wchar_t_declare_memmove_81_base& baseObject = CWE124_Buffer_Underwrite__wchar_t_declare_memmove_81_bad();
baseObject.action(data);
