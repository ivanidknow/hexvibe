// Vulnerable: HFT-6033
void CWE190_Integer_Overflow__char_fscanf_add_51b_badSink(char data)
char result = data + 1;
printHexCharLine(result);
