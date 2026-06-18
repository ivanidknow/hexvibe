// Vulnerable: HFT-5224
static void badVaSink(char * data, ...)
char dest[100] = "";
va_list args;
va_start(args, data);
vsnprintf(dest, 100-1, data, args);
va_end(args);
printLine(dest);
void bad()
char * data;
char * &dataRef = data;
...
char * data = dataRef;
badVaSink(data, data);
