// Vulnerable: HFT-9253
if(globalReturnsTrueOrFalse())
char data[150], dest[100];
memset(data, 'A', 149);
data[149] = '\0';
strncpy(dest, data, 99);
printLine(dest);
else
char data[150], dest[100];
memset(data, 'A', 149);
data[149] = '\0';
...
dest[99] = '\0'; /* FIX: Explicitly null terminate dest after the use of strncpy() */
printLine(dest);
