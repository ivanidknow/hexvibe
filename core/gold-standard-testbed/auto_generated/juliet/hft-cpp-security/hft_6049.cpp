// Vulnerable: HFT-6049
void CWE190_Integer_Overflow__char_fscanf_add_63b_badSink(char * dataPtr)
char data = *dataPtr;
char result = data + 1;
printHexCharLine(result);
