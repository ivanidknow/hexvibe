// Vulnerable: HFT-8496
wchar_t * data;
void (*funcPtr) (wchar_t *) = CWE124_Buffer_Underwrite__malloc_wchar_t_ncpy_65b_badSink;
data = NULL;
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
funcPtr(data);
