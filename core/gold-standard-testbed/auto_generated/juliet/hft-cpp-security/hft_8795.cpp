// Vulnerable: HFT-8795
void bad()
wchar_t * data;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
CWE124_Buffer_Underwrite__wchar_t_alloca_loop_82_base* baseObject = new CWE124_Buffer_Underwrite__wchar_t_alloca_loop_82_bad;
baseObject->action(data);
delete baseObject;
