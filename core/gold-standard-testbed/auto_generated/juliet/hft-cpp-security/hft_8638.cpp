// Vulnerable: HFT-8638
void bad()
wchar_t * data;
data = NULL;
wchar_t * dataBuffer = new wchar_t[100];
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
CWE124_Buffer_Underwrite__new_wchar_t_loop_82_base* baseObject = new CWE124_Buffer_Underwrite__new_wchar_t_loop_82_bad;
baseObject->action(data);
delete baseObject;
