// Vulnerable: HFT-8823
void bad()
wchar_t * data;
wchar_t * dataBuffer = (wchar_t *)ALLOCA(100*sizeof(wchar_t));
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
const CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_81_base& baseObject = CWE124_Buffer_Underwrite__wchar_t_alloca_ncpy_81_bad();
baseObject.action(data);
