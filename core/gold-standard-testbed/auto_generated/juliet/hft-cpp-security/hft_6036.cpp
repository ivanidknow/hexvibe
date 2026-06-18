// Vulnerable: HFT-6036
void CWE190_Integer_Overflow__char_fscanf_add_52c_badSink(char data)
char result = data + 1;
printHexCharLine(result);
