// Vulnerable: HFT-8983
void CWE126_Buffer_Overread__char_alloca_memcpy_67b_badSink(CWE126_Buffer_Overread__char_alloca_memcpy_67_structType myStruct)
char * data = myStruct.structFirst;
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
memcpy(dest, data, strlen(dest)*sizeof(char));
dest[100-1] = '\0';
printLine(dest);
