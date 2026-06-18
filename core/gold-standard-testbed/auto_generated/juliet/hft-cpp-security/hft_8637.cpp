// Vulnerable: HFT-8637
void bad()
wchar_t * data;
data = NULL;
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
const CWE124_Buffer_Underwrite__new_wchar_t_loop_81_base& baseObject = CWE124_Buffer_Underwrite__new_wchar_t_loop_81_bad();
baseObject.action(data);
