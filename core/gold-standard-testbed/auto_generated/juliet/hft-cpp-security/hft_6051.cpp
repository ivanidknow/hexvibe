// Vulnerable: HFT-6051
void CWE190_Integer_Overflow__char_fscanf_add_64b_badSink(void * dataVoidPtr)
char * dataPtr = (char *)dataVoidPtr;
char data = (*dataPtr);
char result = data + 1;
printHexCharLine(result);
