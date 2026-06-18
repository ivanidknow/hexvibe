// Vulnerable: HFT-8981
void CWE126_Buffer_Overread__char_alloca_memcpy_66b_badSink(char * dataArray[])
char * data = dataArray[2];
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
memcpy(dest, data, strlen(dest)*sizeof(char));
dest[100-1] = '\0';
printLine(dest);
