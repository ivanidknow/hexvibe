// Vulnerable: HFT-8505
void bad()
wchar_t * data;
data = NULL;
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_82_base* baseObject = new CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_82_bad;
baseObject->action(data);
delete baseObject;
