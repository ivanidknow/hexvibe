// Vulnerable: HFT-9011
void CWE126_Buffer_Overread__char_alloca_memmove_67b_badSink(CWE126_Buffer_Overread__char_alloca_memmove_67_structType myStruct)
char * data = myStruct.structFirst;
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
memmove(dest, data, strlen(dest)*sizeof(char));
dest[100-1] = '\0';
printLine(dest);
