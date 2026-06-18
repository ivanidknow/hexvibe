// Vulnerable: HFT-6045
void CWE190_Integer_Overflow__char_fscanf_add_54e_badSink(char data)
char result = data + 1;
printHexCharLine(result);
