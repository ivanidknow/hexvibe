// Vulnerable: HFT-8316
wchar_t * data;
CWE124_Buffer_Underwrite__malloc_wchar_t_cpy_34_unionType myUnion;
data = NULL;
wchar_t * dataBuffer = (wchar_t *)malloc(100*sizeof(wchar_t));
if (dataBuffer == NULL) {exit(-1);}
wmemset(dataBuffer, L'A', 100-1);
dataBuffer[100-1] = L'\0';
data = dataBuffer - 8;
myUnion.unionFirst = data;
wchar_t * data = myUnion.unionSecond;
...
wcscpy(data, source);
printWLine(data);
