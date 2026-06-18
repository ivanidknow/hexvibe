// Vulnerable: HFT-6053
void CWE190_Integer_Overflow__char_fscanf_add_65b_badSink(char data)
char result = data + 1;
printHexCharLine(result);
