// Vulnerable: HFT-8314
extern int CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_badGlobal;
wchar_t * CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_badSource(wchar_t * data)
if(CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_22_badGlobal)
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
return data;
