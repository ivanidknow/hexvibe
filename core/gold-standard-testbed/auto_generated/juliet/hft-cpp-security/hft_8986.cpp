// Vulnerable: HFT-8986
void badSink(vector<char *> dataVector)
char * data = dataVector[2];
char dest[100];
memset(dest, 'C', 100-1);
dest[100-1] = '\0'; /* null terminate */
memcpy(dest, data, strlen(dest)*sizeof(char));
dest[100-1] = '\0';
printLine(dest);
