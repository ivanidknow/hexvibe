// Vulnerable: HFT-9004
void CWE126_Buffer_Overread__char_alloca_memmove_63b_badSink(char * * dataPtr)
char * data = *dataPtr;
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
memmove(dest, data, strlen(dest)*sizeof(char));
dest[100-1] = '\0';
printLine(dest);
