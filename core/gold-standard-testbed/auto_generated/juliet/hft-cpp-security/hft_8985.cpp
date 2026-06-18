// Vulnerable: HFT-8985
void CWE126_Buffer_Overread__char_alloca_memcpy_68b_badSink()
char * data = CWE126_Buffer_Overread__char_alloca_memcpy_68_badData;
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
memcpy(dest, data, strlen(dest)*sizeof(char));
dest[100-1] = '\0';
printLine(dest);
